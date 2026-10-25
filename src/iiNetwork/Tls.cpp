#include <iiNetwork/Tls.h>
#include "CertificateInternal.h"
#include "ProtocolInternal.h"
#include "SystemTrustInternal.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <algorithm>
#include <deque>
#include <set>
#include <utility>

namespace ii::network
{
namespace
{
using namespace std::chrono_literals;
auto failure(std::string message, ErrorCode code = ErrorCode::authentication_failed)
{
    auto error = ERR_get_error();
    if (error) { char text[256]{}; ERR_error_string_n(error, text, sizeof(text)); message += ": "; message += text; }
    return detail::fail(Layer::presentation, code, std::move(message));
}
int version(TlsVersion value) { return value == TlsVersion::tls1_2 ? TLS1_2_VERSION : TLS1_3_VERSION; }
bool callbacks(const ByteStream& stream)
{ return stream.connected || stream.readable || stream.disconnected || stream.drained || stream.read_closed || stream.failed || stream.bytes_written; }
void detach(ByteStream& stream)
{ stream.connected = {}; stream.readable = {}; stream.disconnected = {}; stream.drained = {}; stream.read_closed = {}; stream.failed = {}; stream.bytes_written = {}; }
bool hostname(std::string_view name)
{ return !name.empty() && name.size() <= 253 && std::none_of(name.begin(), name.end(), [](unsigned char c) { return c <= 32 || c == 127; }); }
bool stream_options_valid(const TlsStreamOptions& options)
{
    return options.handshake_timeout.count() > 0 && options.handshake_timeout <= std::chrono::hours(24) &&
        options.cipher_bytes >= 16384 && options.cipher_bytes <= 64 * 1024 * 1024 &&
        options.receive_bytes <= 64 * 1024 * 1024 && options.pending_bytes <= 64 * 1024 * 1024;
}
}
struct TlsContext::Impl
{
    SSL_CTX* context = nullptr; TlsRole role; TlsOptions options; std::vector<unsigned char> alpn;
    ~Impl() { SSL_CTX_free(context); }
};
TlsContext::TlsContext(std::shared_ptr<Impl> impl) : p_(std::move(impl)) {}
TlsContext::~TlsContext() = default;
TlsRole TlsContext::role() const { return p_->role; }
Result<std::shared_ptr<TlsContext>> TlsContext::client(TlsOptions options) { return create(TlsRole::client, std::move(options)); }
Result<std::shared_ptr<TlsContext>> TlsContext::server(TlsOptions options) { return create(TlsRole::server, std::move(options)); }
Result<std::shared_ptr<TlsContext>> TlsContext::create(TlsRole role, TlsOptions options)
{
    ERR_clear_error(); auto valid = validate(options.policy); if (!valid) return std::unexpected(valid.error());
    if (options.verification_depth < 1 || options.verification_depth > 128 ||
        (role == TlsRole::client && options.require_client_certificate) ||
        (role == TlsRole::server && options.policy.identity.certificate_chain_file.empty() && options.policy.identity.certificate_chain_pem.empty()) ||
        (role == TlsRole::server && options.policy.trusted_certificate_sha256) ||
        (role == TlsRole::server && options.policy.public_key_sha256 && !options.require_client_certificate))
        return failure("Invalid TLS role, identity or verification options", ErrorCode::invalid_argument);
    auto impl = std::make_shared<Impl>(); impl->role = role; impl->options = std::move(options);
    std::set<std::string> seen;
    for (const auto& name : impl->options.alpn_protocols)
    {
        if (name.empty() || name.size() > 255 || !seen.insert(name).second || impl->alpn.size() + name.size() + 1 > 65535)
            return failure("Invalid ALPN protocol list", ErrorCode::invalid_argument);
        impl->alpn.push_back(static_cast<unsigned char>(name.size())); impl->alpn.insert(impl->alpn.end(), name.begin(), name.end());
    }
    impl->context = SSL_CTX_new(TLS_method());
    if (!impl->context || SSL_CTX_set_min_proto_version(impl->context, version(impl->options.policy.minimum)) != 1 ||
        SSL_CTX_set_max_proto_version(impl->context, version(impl->options.policy.maximum)) != 1) return failure("TLS context creation failed");
    SSL_CTX_set_options(impl->context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify_depth(impl->context, impl->options.verification_depth);
    bool verify = role == TlsRole::client || impl->options.require_client_certificate;
    SSL_CTX_set_verify(impl->context, verify ? SSL_VERIFY_PEER | (role == TlsRole::server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0) : SSL_VERIFY_NONE, nullptr);
    if (impl->options.policy.trusted_certificate_sha256)
    {
        SSL_CTX_set_app_data(impl->context, impl.get());
        SSL_CTX_set_verify(impl->context, SSL_VERIFY_PEER, +[](int valid, X509_STORE_CTX* store) -> int
        {
            if (valid) return 1;
            // Only the chain/hostname trust decision is replaced by the exact
            // authenticated leaf pin. Expiry, purpose and weak keys still fail.
            switch (X509_STORE_CTX_get_error(store))
            {
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            case X509_V_ERR_CERT_UNTRUSTED:
            case X509_V_ERR_HOSTNAME_MISMATCH:
            case X509_V_ERR_IP_ADDRESS_MISMATCH: break;
            default: return 0;
            }
            auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
            auto* config = static_cast<Impl*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
            auto* leaf = X509_STORE_CTX_get0_cert(store);
            std::array<unsigned char, 32> digest{}; unsigned count = 0;
            return config && config->options.policy.trusted_certificate_sha256 && leaf &&
                X509_digest(leaf, EVP_sha256(), digest.data(), &count) == 1 && count == digest.size() &&
                CRYPTO_memcmp(digest.data(), config->options.policy.trusted_certificate_sha256->data(), digest.size()) == 0;
        });
    }
    auto& policy = impl->options.policy;
    if (!policy.ca_file.empty() || !policy.ca_directory.empty())
    {
        if (SSL_CTX_load_verify_locations(impl->context, policy.ca_file.empty() ? nullptr : policy.ca_file.c_str(),
                policy.ca_directory.empty() ? nullptr : policy.ca_directory.c_str()) != 1) return failure("TLS trust store load failed");
    }
    else if (verify && !policy.trusted_certificate_sha256 && !detail::load_system_trust(impl->context)) return failure("System TLS trust store load failed");
    if (!policy.identity.certificate_chain_pem.empty())
    {
        auto certs = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(policy.identity.certificate_chain_pem.data(), static_cast<int>(policy.identity.certificate_chain_pem.size())), BIO_free);
        auto keys = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(policy.identity.private_key_pem.data(), static_cast<int>(policy.identity.private_key_pem.size())), BIO_free);
        auto cert = std::unique_ptr<X509, decltype(&X509_free)>(certs ? PEM_read_bio_X509(certs.get(), nullptr, nullptr, nullptr) : nullptr, X509_free);
        auto no_prompt = +[](char*, int, int, void*) -> int { return 0; };
        auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(keys ? PEM_read_bio_PrivateKey(keys.get(), nullptr, no_prompt, nullptr) : nullptr, EVP_PKEY_free);
        bool loaded = cert && key && SSL_CTX_use_certificate(impl->context, cert.get()) == 1 &&
            SSL_CTX_use_PrivateKey(impl->context, key.get()) == 1 && SSL_CTX_check_private_key(impl->context) == 1;
        if (loaded)
            while (auto* extra = PEM_read_bio_X509(certs.get(), nullptr, nullptr, nullptr))
                if (SSL_CTX_add_extra_chain_cert(impl->context, extra) != 1) { X509_free(extra); loaded = false; break; }
        ERR_clear_error();
        OPENSSL_cleanse(policy.identity.private_key_pem.data(), policy.identity.private_key_pem.size());
        policy.identity.private_key_pem.clear();
        if (!loaded) return failure("TLS in-memory certificate/key load or match failed");
    }
    if (!policy.identity.certificate_chain_file.empty())
    {
        auto& password = policy.identity.private_key_password;
        SSL_CTX_set_default_passwd_cb_userdata(impl->context, &password);
        SSL_CTX_set_default_passwd_cb(impl->context, +[](char* output, int size, int, void* data)
        {
            const auto& password = *static_cast<const std::string*>(data);
            if (size <= 0 || password.size() >= static_cast<std::size_t>(size)) return 0;
            std::copy(password.begin(), password.end(), output); return static_cast<int>(password.size());
        });
        bool loaded = SSL_CTX_use_certificate_chain_file(impl->context, policy.identity.certificate_chain_file.c_str()) == 1 &&
            SSL_CTX_use_PrivateKey_file(impl->context, policy.identity.private_key_file.c_str(), SSL_FILETYPE_PEM) == 1 &&
            SSL_CTX_check_private_key(impl->context) == 1;
        SSL_CTX_set_default_passwd_cb_userdata(impl->context, nullptr); SSL_CTX_set_default_passwd_cb(impl->context, nullptr);
        OPENSSL_cleanse(password.data(), password.size()); password.clear();
        if (!loaded) return failure("TLS certificate/key load or match failed");
    }
    if (role == TlsRole::server && !impl->alpn.empty())
        SSL_CTX_set_alpn_select_cb(impl->context, +[](SSL*, const unsigned char** out, unsigned char* size,
            const unsigned char* input, unsigned input_size, void* data) -> int
        {
            auto& policy = *static_cast<Impl*>(data); unsigned char* selected = nullptr;
            int result = SSL_select_next_proto(&selected, size, policy.alpn.data(), static_cast<unsigned>(policy.alpn.size()), input, input_size);
            if (result != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_NOACK;
            *out = selected; return SSL_TLSEXT_ERR_OK;
        }, impl.get());
    return std::shared_ptr<TlsContext>(new TlsContext(std::move(impl)));
}
struct TlsStream::Impl : std::enable_shared_from_this<TlsStream::Impl>
{
    runtime::EventLoop& loop; TlsStream* owner; std::shared_ptr<TlsContext> context;
    TlsStreamOptions options; std::unique_ptr<ByteStream> stream; SSL* ssl = nullptr; runtime::TaskToken tick;
    TlsState state = TlsState::idle; bool alive = true, pumping = false, closing = false, peer_notify = false, was_pending = false;
    std::string incoming, error, cipher_pending; std::deque<std::string> outgoing; std::size_t offset = 0, queued = 0;
    StreamStatistics statistics; std::optional<TlsConnectionInfo> info;
    runtime::Clock::time_point started{}, close_deadline{};
    Impl(runtime::EventLoop& value, TlsStream* parent, std::shared_ptr<TlsContext> ctx, TlsStreamOptions opts)
        : loop(value), owner(parent), context(std::move(ctx)), options(opts) {}
    ~Impl() { SSL_free(ssl); }
    std::size_t pending() const
    { return queued + cipher_pending.size() + (ssl ? BIO_ctrl_pending(SSL_get_wbio(ssl)) : 0) + (stream ? stream->pending_bytes() : 0); }
    void stop(std::string message = {}, bool notify = true)
    {
        bool running = state != TlsState::closed && state != TlsState::failed && state != TlsState::idle;
        tick.cancel(); error = std::move(message); state = error.empty() ? TlsState::closed : TlsState::failed;
        if (stream) { detach(*stream); stream->close(); }
        SSL_free(std::exchange(ssl, nullptr)); outgoing.clear(); queued = offset = 0; cipher_pending.clear(); closing = false;
        if (!alive || !notify || !running) return;
        auto failed = owner->failed; auto disconnected = owner->disconnected;
        if (!error.empty() && failed) failed(error);
        if (alive && disconnected) disconnected();
    }
    bool flush()
    {
        if (!ssl || !stream || !stream->is_connected()) return false;
        auto* output = SSL_get_wbio(ssl);
        for (unsigned i = 0; i < 64; ++i)
        {
            if (cipher_pending.empty())
            {
                auto count = BIO_ctrl_pending(output); if (!count) return true;
                std::array<char, 16384> bytes{};
                int got = BIO_read(output, bytes.data(), static_cast<int>(std::min<std::size_t>(count, bytes.size())));
                if (got <= 0) { stop("TLS output BIO failed"); return false; }
                cipher_pending.assign(bytes.data(), got);
            }
            if (stream->pending_bytes() > options.cipher_bytes - cipher_pending.size()) return false;
            if (!stream->write(cipher_pending)) return false;
            cipher_pending.clear();
        }
        return !BIO_ctrl_pending(output);
    }
    bool secured()
    {
        const bool verify = context->role() == TlsRole::client || context->p_->options.require_client_certificate;
        auto certificate = std::unique_ptr<X509, decltype(&X509_free)>(SSL_get1_peer_certificate(ssl), X509_free);
        const bool pinned = context->p_->options.policy.trusted_certificate_sha256.has_value();
        if (verify && (!certificate || (!pinned && SSL_get_verify_result(ssl) != X509_V_OK))) { stop("TLS peer certificate verification failed"); return false; }
        TlsConnectionInfo value; value.protocol = SSL_get_version(ssl); value.cipher = SSL_get_cipher_name(ssl);
        value.peer_verified = verify && certificate; value.session_reused = SSL_session_reused(ssl) != 0;
        const unsigned char* alpn = nullptr; unsigned length = 0; SSL_get0_alpn_selected(ssl, &alpn, &length);
        if (length) value.alpn.assign(reinterpret_cast<const char*>(alpn), length);
        if (auto* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) value.server_name = name;
        if (certificate)
        {
            auto parsed = detail::certificate_info(certificate.get());
            if (!parsed) { stop(parsed.error().message); return false; }
            value.peer_certificate = std::move(*parsed);
        }
        if (auto pin = context->p_->options.policy.public_key_sha256; pin &&
            (!value.peer_certificate || CRYPTO_memcmp(pin->data(), value.peer_certificate->public_key_sha256.data(), 32)))
        { stop("TLS public key pin mismatch"); return false; }
        if (auto pin = context->p_->options.policy.trusted_certificate_sha256; pin &&
            (!value.peer_certificate || !value.peer_certificate->valid_at() ||
             CRYPTO_memcmp(pin->data(), value.peer_certificate->certificate_sha256.data(), pin->size())))
        { stop("TLS trusted certificate mismatch or expiry"); return false; }
        info = std::move(value); state = TlsState::secured;
        auto callback = owner->connected; if (callback) callback();
        return alive && ssl && state == TlsState::secured;
    }
    void pump()
    {
        if (!alive || !ssl || pumping) return;
        pumping = true;
        struct Reset { bool& value; ~Reset() { value = false; } } reset{pumping};
        if (!stream || !stream->is_connected()) return;
        if (state == TlsState::connecting) { state = TlsState::handshaking; started = runtime::Clock::now(); }
        if (state == TlsState::handshaking && runtime::Clock::now() - started >= options.handshake_timeout)
        { stop("TLS handshake deadline elapsed"); return; }
        auto encrypted = stream->read();
        if (encrypted.size() > options.cipher_bytes || BIO_ctrl_pending(SSL_get_rbio(ssl)) > options.cipher_bytes - encrypted.size())
        { stop("TLS encrypted receive limit exceeded"); return; }
        if (!encrypted.empty() && BIO_write(SSL_get_rbio(ssl), encrypted.data(), static_cast<int>(encrypted.size())) != static_cast<int>(encrypted.size()))
        { stop("TLS input BIO failed"); return; }
        if (state == TlsState::handshaking)
        {
            ERR_clear_error(); int result = SSL_do_handshake(ssl); int code = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, result);
            if (result == 1) { if (!secured()) return; }
            else if (code != SSL_ERROR_WANT_READ && code != SSL_ERROR_WANT_WRITE)
            {
                // The OpenSSL error queue is thread-local and may be drained
                // by another adapter callback. Verification status belongs to
                // this SSL session and preserves the certificate failure kind.
                const auto verification = SSL_get_verify_result(ssl);
                auto message = verification == X509_V_OK ? std::string("TLS handshake failed")
                    : std::string("TLS peer certificate verification failed: ") + X509_verify_cert_error_string(verification);
                stop(failure(std::move(message)).error().message); return;
            }
            flush(); if (!ssl || state == TlsState::handshaking) return;
        }
        if (state != TlsState::secured && state != TlsState::closing) return;
        for (unsigned i = 0; i < 64 && ssl && !outgoing.empty(); ++i)
        {
            if (BIO_ctrl_pending(SSL_get_wbio(ssl)) + cipher_pending.size() + stream->pending_bytes() >= options.cipher_bytes) break;
            auto& front = outgoing.front(); auto size = std::min<std::size_t>(front.size() - offset, 16384); std::size_t written = 0;
            ERR_clear_error(); int result = SSL_write_ex(ssl, front.data() + offset, size, &written); int code = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, result);
            if (result != 1)
            {
                if (code != SSL_ERROR_WANT_READ && code != SSL_ERROR_WANT_WRITE) { stop(failure("TLS write failed").error().message); return; }
                break;
            }
            queued -= written; offset += written; statistics.written_bytes += written; ++statistics.write_operations;
            if (offset == front.size()) { outgoing.pop_front(); offset = 0; }
            auto callback = owner->bytes_written; if (callback) callback(written);
            if (!alive || !ssl) return;
        }
        flush(); if (!ssl) return;
        bool received = false;
        for (unsigned i = 0; i < 64; ++i)
        {
            std::array<char, 16384> bytes{}; std::size_t size = 0;
            ERR_clear_error(); int result = SSL_read_ex(ssl, bytes.data(), bytes.size(), &size); int code = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, result);
            if (result != 1)
            {
                if (code == SSL_ERROR_ZERO_RETURN) { peer_notify = true; closing = true; state = TlsState::closing; close_deadline = runtime::Clock::now() + 1s; break; }
                if (code != SSL_ERROR_WANT_READ && code != SSL_ERROR_WANT_WRITE) { stop(failure("TLS read failed").error().message); return; }
                break;
            }
            if (incoming.size() > options.receive_bytes || size > options.receive_bytes - incoming.size()) { stop("TLS plaintext receive limit exceeded"); return; }
            incoming.append(bytes.data(), size); statistics.received_bytes += size; ++statistics.read_operations; received = true;
        }
        if (received) { auto callback = owner->readable; if (callback) callback(); if (!alive || !ssl) return; }
        if (closing && outgoing.empty())
        {
            ERR_clear_error(); int result = SSL_shutdown(ssl); int code = result >= 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, result);
            if (result < 0 && code != SSL_ERROR_WANT_READ && code != SSL_ERROR_WANT_WRITE) { stop(failure("TLS shutdown failed").error().message); return; }
            flush(); if (!ssl) return;
            if (!pending() && (peer_notify || result == 1)) { stop(); return; }
        }
        if (closing && runtime::Clock::now() >= close_deadline) { stop(); return; }
        auto count = pending();
        if (was_pending && !count) { was_pending = false; auto callback = owner->drained; if (callback) callback(); }
    }
};
TlsStream::TlsStream(runtime::EventLoop& loop, std::shared_ptr<TlsContext> context, TlsStreamOptions options)
    : p_(std::make_shared<Impl>(loop, this, std::move(context), options)) {}
TlsStream::~TlsStream() { p_->alive = false; p_->stop({}, false); }
Result<void> TlsStream::prepare(std::unique_ptr<ByteStream> stream, std::string name, bool connecting)
{
    auto& p = *p_;
    if (!p.context || !stream || callbacks(*stream) || (!connecting && !stream->is_connected()) ||
        (p.context->role() == TlsRole::client && !hostname(name)) ||
        !stream_options_valid(p.options))
        return failure("TLS requires a context, callback-free stream, valid peer name and bounded options", ErrorCode::invalid_argument);
    p.stop({}, false); p.stream = std::move(stream); p.error.clear(); p.info.reset(); p.incoming.clear(); p.statistics = {};
    p.peer_notify = p.closing = p.was_pending = false;
    p.ssl = SSL_new(p.context->p_->context);
    BIO* input = BIO_new(BIO_s_mem()); BIO* output = BIO_new(BIO_s_mem());
    if (!p.ssl || !input || !output)
    { BIO_free(input); BIO_free(output); p.stop("TLS BIO allocation failed", false); return failure(p.error, ErrorCode::unavailable); }
    BIO_set_mem_eof_return(input, -1); BIO_set_mem_eof_return(output, -1); SSL_set_bio(p.ssl, input, output);
    SSL_set_mode(p.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (p.context->role() == TlsRole::client)
    {
        SSL_set_connect_state(p.ssl);
        if (SSL_set1_host(p.ssl, name.c_str()) != 1 ||
            (!IpAddress::parse(name) && SSL_set_tlsext_host_name(p.ssl, name.c_str()) != 1) ||
            (!p.context->p_->alpn.empty() && SSL_set_alpn_protos(p.ssl, p.context->p_->alpn.data(), static_cast<unsigned>(p.context->p_->alpn.size())) != 0))
        { p.stop("TLS hostname/SNI/ALPN setup failed", false); return failure(p.error); }
    }
    else SSL_set_accept_state(p.ssl);
    p.stream->receive_limit(p.options.cipher_bytes); p.stream->send_limit(p.options.cipher_bytes);
    auto weak = std::weak_ptr<Impl>(p_);
    p.stream->readable = [weak] { if (auto keep = weak.lock()) keep->pump(); };
    p.stream->connected = [weak] { if (auto keep = weak.lock()) { keep->state = TlsState::handshaking; keep->started = runtime::Clock::now(); } };
    p.stream->failed = [weak](std::string error) { if (auto keep = weak.lock()) keep->stop(std::move(error)); };
    p.stream->disconnected = [weak]
    { if (auto keep = weak.lock()) keep->stop(keep->peer_notify ? "" : "TLS transport closed without close_notify"); };
    p.state = connecting ? TlsState::connecting : TlsState::handshaking; p.started = runtime::Clock::now();
    p.tick = p.loop.every(5ms, [weak] { if (auto keep = weak.lock()) keep->pump(); }).token;
    if (!p.tick.pending()) { p.stop("Core TLS dispatch admission failed", false); return failure(p.error, ErrorCode::unavailable); }
    return {};
}
Result<void> TlsStream::connect(IpEndpoint endpoint, std::string name, TcpOptions options)
{
    if (!p_->context || p_->context->role() != TlsRole::client || !hostname(name)) return failure("TLS connect requires a client context and peer name", ErrorCode::invalid_argument);
    auto stream = std::make_unique<Tcp>(p_->loop); auto connected = stream->connect(endpoint, std::move(options));
    if (!connected) return connected;
    return prepare(std::move(stream), std::move(name), true);
}
Result<void> TlsStream::attach(std::unique_ptr<ByteStream> stream, std::string name) { return prepare(std::move(stream), std::move(name), false); }
bool TlsStream::write(std::string_view bytes)
{
    auto& p = *p_;
    if (p.state != TlsState::secured || p.queued > p.options.pending_bytes || bytes.size() > p.options.pending_bytes - p.queued || p.outgoing.size() >= 1024) return false;
    if (bytes.empty()) return true;
    p.outgoing.emplace_back(bytes); p.queued += bytes.size(); p.was_pending = true; return true;
}
std::string TlsStream::read() { return std::exchange(p_->incoming, {}); }
std::string TlsStream::read_some(std::size_t maximum)
{ auto count = std::min(maximum, p_->incoming.size()); auto out = p_->incoming.substr(0, count); p_->incoming.erase(0, count); return out; }
std::string TlsStream::peek(std::size_t maximum) const { return p_->incoming.substr(0, maximum); }
std::size_t TlsStream::available_bytes() const { return p_->incoming.size(); }
std::size_t TlsStream::pending_bytes() const { return p_->pending(); }
void TlsStream::receive_limit(std::size_t bytes) { p_->options.receive_bytes = std::min<std::size_t>(bytes, 64 * 1024 * 1024); }
void TlsStream::send_limit(std::size_t bytes) { p_->options.pending_bytes = std::min<std::size_t>(bytes, 64 * 1024 * 1024); }
void TlsStream::close(bool flush)
{
    if (flush && p_->state == TlsState::secured)
    { p_->closing = true; p_->state = TlsState::closing; p_->close_deadline = runtime::Clock::now() + 1s; return; }
    p_->stop({}, false);
}
bool TlsStream::is_connected() const { return p_->state == TlsState::secured || p_->state == TlsState::closing; }
SocketState TlsStream::state() const
{
    if (p_->state == TlsState::secured) return SocketState::connected;
    if (p_->state == TlsState::connecting || p_->state == TlsState::handshaking) return SocketState::connecting;
    if (p_->state == TlsState::closing) return SocketState::closing;
    return p_->state == TlsState::failed ? SocketState::failed : SocketState::closed;
}
std::string TlsStream::error() const { return p_->error; }
StreamStatistics TlsStream::statistics() const { return p_->statistics; }
std::optional<IpEndpoint> TlsStream::local_endpoint() const { return p_->stream ? p_->stream->local_endpoint() : std::nullopt; }
std::optional<IpEndpoint> TlsStream::peer_endpoint() const { return p_->stream ? p_->stream->peer_endpoint() : std::nullopt; }
std::optional<PeerCredentials> TlsStream::peer_credentials() const { return p_->stream ? p_->stream->peer_credentials() : std::nullopt; }
TlsState TlsStream::tls_state() const { return p_->state; }
std::optional<TlsConnectionInfo> TlsStream::connection_info() const { return p_->info; }
struct TlsListener::Impl
{
    runtime::EventLoop& loop; Listener listener; TlsListener* owner; std::shared_ptr<TlsContext> context;
    TlsStreamOptions options; bool alive = true;
    Impl(runtime::EventLoop& value, TlsListener* parent, std::shared_ptr<TlsContext> ctx, TlsStreamOptions opts)
        : loop(value), listener(value), owner(parent), context(std::move(ctx)), options(opts) {}
};
TlsListener::TlsListener(runtime::EventLoop& loop, std::shared_ptr<TlsContext> context, TlsStreamOptions options)
    : p_(std::make_shared<Impl>(loop, this, std::move(context), options))
{
    p_->listener.accepted = [weak = std::weak_ptr<Impl>(p_)](std::unique_ptr<Tcp> stream)
    {
        auto keep = weak.lock(); if (!keep || !keep->alive) return;
        auto secured = std::make_unique<TlsStream>(keep->loop, keep->context, keep->options); auto result = secured->attach(std::move(stream));
        if (!result) { auto callback = keep->owner->failed; if (callback) callback(result.error().message); return; }
        auto callback = keep->owner->accepted; if (callback) callback(std::move(secured));
    };
}
TlsListener::~TlsListener() { p_->alive = false; close(); }
Result<void> TlsListener::listen(IpEndpoint endpoint, ListenerOptions options)
{
    if (!p_->context || p_->context->role() != TlsRole::server || !stream_options_valid(p_->options))
        return failure("TLS listener requires a server context and valid stream limits", ErrorCode::invalid_argument);
    return p_->listener.listen(endpoint, std::move(options));
}
void TlsListener::close() { p_->listener.close(); }
std::uint16_t TlsListener::port() const { return p_->listener.port(); }
std::string TlsListener::error() const { return p_->listener.error(); }
} // namespace ii::network
