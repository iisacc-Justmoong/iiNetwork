#include <iiNetwork/Peer.h>
#include <iiJson/Json.h>
#include "ProtocolInternal.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <utility>

namespace ii::network
{
namespace
{
using namespace std::chrono_literals;
using Value = core::Value;
using Object = Value::Object;
using Clock = runtime::Clock;
Error peer_error(ErrorCode code, std::string message, Layer layer = Layer::application)
{ return {code, layer, std::move(message)}; }
auto reject(ErrorCode code, std::string message)
{ return std::unexpected(peer_error(code, std::move(message))); }
bool name_valid(std::string_view name)
{
    return !name.empty() && name.size() <= 128 && std::all_of(name.begin(), name.end(), [](unsigned char c)
    { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '/' || c == ':' || c == '-'; });
}
bool identity_valid(std::string_view value)
{ return !value.empty() && value.size() <= 128 && std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c == 127; }); }
Result<void> validate(std::string_view identity, const PeerLimits& limits)
{
    if (!identity_valid(identity) || limits.frame_bytes < 512 || limits.frame_bytes > 16 * 1024 * 1024 ||
        limits.pending_bytes < limits.frame_bytes + 4 || limits.pending_bytes > 64 * 1024 * 1024 ||
        !limits.connections || limits.connections > 4096 || !limits.requests || limits.requests > 4096 ||
        !limits.operations || limits.operations > 4096 || limits.handshake_timeout <= 0ms || limits.handshake_timeout > 1h ||
        limits.maximum_call_timeout <= 0ms || limits.maximum_call_timeout > 1h)
        return reject(ErrorCode::invalid_argument, "Peer requires an identity, bounded storage/counts and positive deadlines");
    if (!core::valid_utf8(identity)) return reject(ErrorCode::invalid_argument, "Peer identity is not valid UTF-8");
    return {};
}
bool has_callbacks(const ByteStream& stream)
{ return stream.connected || stream.readable || stream.disconnected || stream.read_closed || stream.drained || stream.bytes_written || stream.failed; }
void detach(ByteStream& stream)
{ stream.connected = {}; stream.readable = {}; stream.disconnected = {}; stream.read_closed = {}; stream.drained = {}; stream.bytes_written = {}; stream.failed = {}; }
const Value* field(const Object& object, std::string_view key)
{ auto found = object.find(std::string(key)); return found == object.end() ? nullptr : &found->second; }
const std::string* text(const Object& object, std::string_view key)
{ auto* value = field(object, key); if (!value) return nullptr; auto typed = value->get<std::string>(); return typed ? &typed->get() : nullptr; }
std::optional<std::int64_t> integer(const Object& object, std::string_view key)
{ auto* value = field(object, key); if (!value) return {}; auto typed = value->get<std::int64_t>(); return typed ? std::optional(typed->get()) : std::nullopt; }
std::optional<std::uint64_t> request_id(const Object& object)
{
    auto* value = text(object, "id"); if (!value || value->empty() || value->size() > 20) return {};
    std::uint64_t result = 0; auto [end, code] = std::from_chars(value->data(), value->data() + value->size(), result);
    if (code != std::errc{} || end != value->data() + value->size() || !result || std::to_string(result) != *value) return {};
    return result;
}
constexpr std::array<std::string_view, 19> error_names{
    "invalid_argument", "malformed", "checksum_mismatch", "too_large", "unsupported", "unavailable", "would_block",
    "closed", "no_route", "ttl_expired", "invalid_state", "expired", "replay", "authentication_failed", "io_error",
    "cancelled", "not_found", "permission_denied", "remote_error"};
struct Services
{
    std::map<std::string, Peer::Handler> operations;
    Peer::Authorizer authorize;
    bool alive = true;
};
} // namespace
struct PeerReply::State
{
    bool pending = true, cancelled = false;
    std::function<Result<void>(Result<Value>)> submit;
};
PeerReply::PeerReply(std::shared_ptr<State> state) : p_(std::move(state)) {}
Result<void> PeerReply::operator()(Result<Value> value) const
{
    if (!p_ || !p_->pending) return reject(p_ && p_->cancelled ? ErrorCode::cancelled : ErrorCode::invalid_state, "Peer reply is no longer pending");
    return p_->submit(std::move(value));
}
bool PeerReply::pending() const { return p_ && p_->pending; }
bool PeerReply::cancelled() const { return !p_ || p_->cancelled; }
struct PeerConnection::Impl : std::enable_shared_from_this<PeerConnection::Impl>
{
    runtime::EventLoop& loop;
    PeerConnection* owner = nullptr;
    std::weak_ptr<PeerConnection> self;
    std::shared_ptr<Services> services;
    std::unique_ptr<ByteStream> stream;
    std::string identity, body;
    SessionId session;
    PeerLimits limits;
    PeerState state = PeerState::connecting;
    std::optional<PeerInfo> info;
    std::optional<Error> last_error;
    std::size_t expected_bytes = 0, remote_frame_bytes = 0;
    std::uint64_t next_request = 1, last_incoming = 0;
    bool alive = true, callbacks_enabled = true, pumping = false, hello_sent = false;
    runtime::TaskToken tick;
    Clock::time_point created = Clock::now();
    struct Pending { Completion complete; Clock::time_point expires; };
    struct Incoming { std::shared_ptr<PeerReply::State> reply; Clock::time_point expires; };
    std::map<std::uint64_t, Pending> outgoing;
    std::map<std::uint64_t, Incoming> incoming;
    std::function<void()> on_ready, on_closed;
    std::function<void(Error)> on_failed;
    Impl(runtime::EventLoop& event_loop, std::string name, PeerLimits bounds, std::shared_ptr<Services> registry,
         std::unique_ptr<ByteStream> transport, SessionId id)
        : loop(event_loop), services(std::move(registry)), stream(std::move(transport)), identity(std::move(name)), session(id), limits(bounds) {}
    bool terminal() const { return state == PeerState::closed || state == PeerState::failed; }
    bool callbacks_live() const { return alive && callbacks_enabled && services->alive; }
    void stop(Error cause, bool notify = true)
    {
        if (!notify) callbacks_enabled = false;
        if (terminal()) return;
        auto retained = self.lock();
        state = cause.code == ErrorCode::closed ? PeerState::closed : PeerState::failed;
        if (state == PeerState::failed) last_error = cause;
        tick.cancel(); detach(*stream); stream->close(); body.clear(); expected_bytes = 0;
        auto pending = std::exchange(outgoing, {});
        for (auto& [id, call] : incoming) { call.reply->pending = false; call.reply->cancelled = true; }
        incoming.clear();
        for (auto& [id, call] : pending)
            if (callbacks_live() && call.complete) call.complete(std::unexpected(cause));
        if (callbacks_live() && state == PeerState::failed)
        {
            auto callback = owner->failed; if (callback) callback(cause);
            if (callbacks_live()) { auto global = on_failed; if (global) global(cause); }
        }
        if (callbacks_live()) { auto callback = owner->disconnected; if (callback) callback(); }
        auto closed = std::move(on_closed); if (closed) closed();
    }
    Result<void> send(Value message)
    {
        if (terminal() || !stream->is_connected()) return reject(ErrorCode::closed, "Peer transport is closed");
        auto maximum = remote_frame_bytes ? std::min(limits.frame_bytes, remote_frame_bytes) : limits.frame_bytes;
        ii::json::Limits bounds; bounds.input_bytes = bounds.output_bytes = bounds.string_bytes = maximum; bounds.items = 65536; bounds.depth = 32;
        auto encoded = ii::json::stringify(message, bounds);
        if (!encoded) return reject(encoded.error().code == ii::json::ErrorCode::limit_exceeded ? ErrorCode::too_large : ErrorCode::invalid_argument, encoded.error().message);
        std::string frame; detail::put32(frame, static_cast<std::uint32_t>(encoded->size())); frame += *encoded;
        if (stream->pending_bytes() > limits.pending_bytes || frame.size() > limits.pending_bytes - stream->pending_bytes() || !stream->write(frame))
            return reject(ErrorCode::would_block, "Peer send queue cannot admit the frame");
        return {};
    }
    Result<void> send_error(std::uint64_t id, Error cause)
    {
        auto code = static_cast<std::size_t>(cause.code);
        if (code >= error_names.size() || static_cast<unsigned>(cause.layer) < 1 || static_cast<unsigned>(cause.layer) > 7 || cause.message.size() > 8192 || !core::valid_utf8(cause.message))
            return reject(ErrorCode::invalid_argument, "Invalid peer response error");
        return send(Value(Object{{"type", Value("error")}, {"id", Value(std::to_string(id))},
            {"code", Value(std::string(error_names[code]))}, {"layer", Value(static_cast<int>(cause.layer))}, {"message", Value(std::move(cause.message))}}));
    }
    void required_error(std::uint64_t id, Error cause)
    { auto sent = send_error(id, std::move(cause)); if (!sent) stop(sent.error()); }
    void malformed(std::string message) { stop(peer_error(ErrorCode::malformed, std::move(message))); }
    bool start()
    {
        stream->receive_limit(limits.frame_bytes * 2 + 8); stream->send_limit(limits.pending_bytes);
        auto weak = weak_from_this();
        stream->connected = [weak] { if (auto keep = weak.lock()) keep->pump(); };
        stream->readable = [weak] { if (auto keep = weak.lock()) keep->pump(); };
        stream->failed = [weak](std::string message) { if (auto keep = weak.lock()) keep->stop(peer_error(ErrorCode::io_error, std::move(message), Layer::transport)); };
        stream->disconnected = [weak]
        {
            if (auto keep = weak.lock(); keep && !keep->terminal())
            {
                if (keep->expected_bytes || keep->stream->available_bytes()) keep->malformed("Peer transport ended inside a frame");
                else if (keep->state != PeerState::ready) keep->malformed("Peer transport closed during negotiation");
                else keep->stop(peer_error(ErrorCode::closed, "Peer disconnected"));
            }
        };
        stream->read_closed = stream->disconnected; // Peer operations require both directions, even on half-close-capable transports.
        tick = loop.every(5ms, [weak] { if (auto keep = weak.lock()) keep->pump(); }).token;
        return tick.pending();
    }
    void establish(const Object& object)
    {
        auto version = integer(object, "version"), maximum = integer(object, "maximum_frame");
        auto* name = text(object, "identity"); auto* id = text(object, "session");
        if (object.size() != 5 || !version || *version != 1 || !maximum || *maximum < 512 || *maximum > 16 * 1024 * 1024 ||
            !name || !identity_valid(*name) || !id)
        { malformed("Invalid peer hello or unsupported peer protocol version"); return; }
        auto parsed = SessionId::parse(*id); if (!parsed) { malformed("Invalid peer session ID"); return; }
        PeerInfo remote; remote.identity = *name; remote.local_session = session; remote.remote_session = *parsed;
        remote.local_endpoint = stream->local_endpoint(); remote.remote_endpoint = stream->peer_endpoint();
        remote.local_credentials = stream->peer_credentials();
        if (auto* tls = dynamic_cast<TlsStream*>(stream.get())) remote.tls = tls->connection_info();
        remote_frame_bytes = static_cast<std::size_t>(*maximum); info = std::move(remote); state = PeerState::ready;
        auto callback = owner->connected; if (callback) callback();
        if (alive && callbacks_enabled && state == PeerState::ready) { auto global = on_ready; if (global) global(); }
    }
    void dispatch_call(const Object& object)
    {
        auto id = request_id(object); auto* operation = text(object, "operation"); auto* arguments = field(object, "arguments");
        auto budget = integer(object, "timeout");
        if (object.size() != 5 || !id || *id <= last_incoming || !operation || !name_valid(*operation) || !arguments ||
            !budget || *budget <= 0 || *budget > std::chrono::duration_cast<std::chrono::milliseconds>(1h).count())
        { malformed("Invalid or repeated incoming peer call"); return; }
        last_incoming = *id;
        auto expires = Clock::now() + std::min(std::chrono::milliseconds(*budget), limits.maximum_call_timeout);
        if (!services->alive) { stop(peer_error(ErrorCode::closed, "Peer service registry is closed")); return; }
        auto found = services->operations.find(*operation);
        if (found == services->operations.end()) { required_error(*id, peer_error(ErrorCode::not_found, "Peer operation is not exposed")); return; }
        auto handler = found->second; auto authorize = services->authorize; bool allowed = true;
        try { if (authorize) allowed = authorize(*info, *operation); } catch (...) { allowed = false; }
        if (terminal() || !alive || !services->alive) return;
        if (!allowed) { required_error(*id, peer_error(ErrorCode::permission_denied, "Peer operation denied")); return; }
        if (Clock::now() >= expires) { required_error(*id, peer_error(ErrorCode::expired, "Peer authorization exceeded the operation deadline")); return; }
        if (incoming.size() >= limits.requests) { required_error(*id, peer_error(ErrorCode::would_block, "Peer incoming call bound reached")); return; }
        auto token = std::make_shared<PeerReply::State>(); auto weak = weak_from_this(); auto call_id = *id;
        token->submit = [weak, call_id](Result<Value> result) -> Result<void>
        {
            auto keep = weak.lock(); if (!keep || keep->state != PeerState::ready) return reject(ErrorCode::closed, "Peer connection is closed");
            auto found = keep->incoming.find(call_id); if (found == keep->incoming.end()) return reject(ErrorCode::cancelled, "Peer call is no longer active");
            if (Clock::now() >= found->second.expires)
            {
                found->second.reply->pending = false; found->second.reply->cancelled = true; keep->incoming.erase(found);
                keep->required_error(call_id, peer_error(ErrorCode::expired, "Peer operation deadline elapsed"));
                return reject(ErrorCode::expired, "Peer reply exceeded its deadline");
            }
            auto sent = result ? keep->send(Value(Object{{"type", Value("result")}, {"id", Value(std::to_string(call_id))}, {"value", std::move(*result)}})) :
                keep->send_error(call_id, std::move(result.error()));
            if (sent) { found->second.reply->pending = false; keep->incoming.erase(found); }
            return sent;
        };
        incoming.emplace(call_id, Incoming{token, expires});
        PeerReply reply(token);
        try { handler(PeerCall{call_id, *operation, *arguments, self.lock()}, reply); }
        catch (...) { if (reply.pending()) { auto sent = reply(std::unexpected(peer_error(ErrorCode::remote_error, "Peer operation handler failed"))); if (!sent && !terminal()) stop(sent.error()); } }
    }
    void dispatch(Value message)
    {
        auto object = message.get<Object>(); if (!object) { malformed("Peer frame must be a JSON object"); return; }
        const auto& fields = object->get(); auto* type = text(fields, "type");
        if (!type) { malformed("Peer frame lacks type"); return; }
        if (state != PeerState::ready)
        {
            if (*type != "hello" || !hello_sent) { malformed("Peer application traffic before mutual hello"); return; }
            establish(fields); return;
        }
        if (*type == "call") { dispatch_call(fields); return; }
        if (*type == "event")
        {
            auto* topic = text(fields, "topic"); auto* value = field(fields, "value");
            if (fields.size() != 3 || !topic || !name_valid(*topic) || !value) { malformed("Invalid peer event"); return; }
            auto callback = owner->received; if (callback) callback(PeerEvent{*topic, *value}); return;
        }
        auto id = request_id(fields);
        if (*type == "cancel")
        {
            if (fields.size() != 2 || !id || *id > last_incoming) { malformed("Invalid peer cancellation"); return; }
            if (auto found = incoming.find(*id); found != incoming.end())
            { found->second.reply->pending = false; found->second.reply->cancelled = true; incoming.erase(found); }
            return;
        }
        if (*type != "result" && *type != "error") { malformed("Unknown peer frame type or repeated hello"); return; }
        if (!id || *id >= next_request) { malformed("Unsolicited peer result"); return; }
        Result<Value> result;
        if (*type == "result")
        {
            auto* value = field(fields, "value"); if (fields.size() != 3 || !value) { malformed("Invalid peer result"); return; }
            result = *value;
        }
        else
        {
            auto* code = text(fields, "code"); auto* message = text(fields, "message"); auto layer = integer(fields, "layer");
            auto named = code ? std::find(error_names.begin(), error_names.end(), *code) : error_names.end();
            if (fields.size() != 5 || named == error_names.end() || !message || message->size() > 8192 || !layer || *layer < 1 || *layer > 7)
            { malformed("Invalid peer error"); return; }
            result = std::unexpected(peer_error(static_cast<ErrorCode>(named - error_names.begin()), *message, static_cast<Layer>(*layer)));
        }
        auto found = outgoing.find(*id); if (found == outgoing.end()) return; // Late reply to a settled/cancelled call.
        if (Clock::now() >= found->second.expires) result = std::unexpected(peer_error(ErrorCode::expired, "Peer request deadline elapsed"));
        auto callback = std::move(found->second.complete); outgoing.erase(found);
        if (callback) callback(std::move(result));
    }
    void deadlines()
    {
        auto now = Clock::now(); std::vector<std::uint64_t> expired;
        for (const auto& [id, call] : incoming) if (now >= call.expires) expired.push_back(id);
        for (auto id : expired)
        {
            auto found = incoming.find(id); if (found == incoming.end()) continue;
            found->second.reply->pending = false; found->second.reply->cancelled = true; incoming.erase(found);
            required_error(id, peer_error(ErrorCode::expired, "Peer operation deadline elapsed")); if (terminal()) return;
        }
        expired.clear(); for (const auto& [id, call] : outgoing) if (now >= call.expires) expired.push_back(id);
        for (auto id : expired)
        {
            auto found = outgoing.find(id); if (found == outgoing.end()) continue;
            auto callback = std::move(found->second.complete); outgoing.erase(found);
            (void)send(Value(Object{{"type", Value("cancel")}, {"id", Value(std::to_string(id))}}));
            if (callback) callback(std::unexpected(peer_error(ErrorCode::expired, "Peer request deadline elapsed")));
            if (!alive || terminal()) return;
        }
    }
    void pump()
    {
        if (!alive || terminal() || pumping) return;
        pumping = true; struct Reset { bool& value; ~Reset() { value = false; } } reset{pumping};
        if (state != PeerState::ready && Clock::now() - created >= limits.handshake_timeout)
        { stop(peer_error(ErrorCode::expired, "Peer negotiation deadline elapsed")); return; }
        if (!stream->is_connected()) return;
        if (state == PeerState::ready) { deadlines(); if (!alive || terminal()) return; }
        if (!hello_sent)
        {
            state = PeerState::negotiating;
            auto sent = send(Value(Object{{"type", Value("hello")}, {"version", Value(1)}, {"identity", Value(identity)},
                {"session", Value(session.string())}, {"maximum_frame", Value(static_cast<std::int64_t>(limits.frame_bytes))}}));
            if (!sent) { stop(sent.error()); return; } hello_sent = true;
        }
        for (unsigned frames = 0; frames < 64 && alive && !terminal(); ++frames)
        {
            if (!expected_bytes)
            {
                if (stream->available_bytes() < 4) break;
                auto prefix = stream->read_some(4); expected_bytes = detail::u32(prefix, 0);
                if (!expected_bytes || expected_bytes > limits.frame_bytes) { stop(peer_error(ErrorCode::too_large, "Peer frame bound exceeded")); return; }
            }
            body += stream->read_some(expected_bytes - body.size());
            if (body.size() != expected_bytes) break;
            ii::json::Limits bounds; bounds.input_bytes = bounds.output_bytes = bounds.string_bytes = limits.frame_bytes; bounds.items = 65536; bounds.depth = 32;
            auto parsed = ii::json::parse(body, bounds); body.clear(); expected_bytes = 0;
            if (!parsed) { malformed("Invalid peer JSON: " + parsed.error().message); return; }
            dispatch(std::move(*parsed));
        }
        if (alive && state == PeerState::ready) deadlines();
    }
};
PeerConnection::PeerConnection(std::shared_ptr<Impl> impl) : p_(std::move(impl)) { p_->owner = this; }
PeerConnection::~PeerConnection() { p_->alive = false; shutdown(false); }
void PeerConnection::shutdown(bool notify) { p_->stop(peer_error(ErrorCode::closed, "Peer connection closed"), notify); }
void PeerConnection::close() { shutdown(true); }
Result<std::uint64_t> PeerConnection::request(std::string operation, Value arguments, Completion complete, std::chrono::milliseconds timeout)
{
    auto& p = *p_;
    if (p.state != PeerState::ready) return reject(ErrorCode::invalid_state, "Peer connection is not ready");
    if (!name_valid(operation) || !complete || timeout <= 0ms || timeout > p.limits.maximum_call_timeout)
        return reject(ErrorCode::invalid_argument, "Invalid peer operation, callback or deadline");
    if (p.outgoing.size() >= p.limits.requests) return reject(ErrorCode::would_block, "Peer outgoing call bound reached");
    if (p.next_request == std::numeric_limits<std::uint64_t>::max()) return reject(ErrorCode::invalid_state, "Peer call sequence exhausted; establish a new link");
    auto id = p.next_request;
    auto sent = p.send(Value(Object{{"type", Value("call")}, {"id", Value(std::to_string(id))}, {"operation", Value(std::move(operation))},
        {"arguments", std::move(arguments)}, {"timeout", Value(timeout.count())}}));
    if (!sent) return std::unexpected(sent.error());
    ++p.next_request; p.outgoing.emplace(id, Impl::Pending{std::move(complete), Clock::now() + timeout}); return id;
}
Result<void> PeerConnection::notify(std::string topic, Value value)
{
    if (p_->state != PeerState::ready) return reject(ErrorCode::invalid_state, "Peer connection is not ready");
    if (!name_valid(topic)) return reject(ErrorCode::invalid_argument, "Invalid peer event topic");
    return p_->send(Value(Object{{"type", Value("event")}, {"topic", Value(std::move(topic))}, {"value", std::move(value)}}));
}
bool PeerConnection::cancel(std::uint64_t id)
{
    auto found = p_->outgoing.find(id); if (found == p_->outgoing.end()) return false;
    p_->outgoing.erase(found); (void)p_->send(Value(Object{{"type", Value("cancel")}, {"id", Value(std::to_string(id))}})); return true;
}
PeerState PeerConnection::state() const { return p_->state; }
std::optional<PeerInfo> PeerConnection::info() const { return p_->info; }
std::optional<Error> PeerConnection::error() const { return p_->last_error; }
std::size_t PeerConnection::pending_requests() const { return p_->outgoing.size(); }
std::size_t PeerConnection::active_requests() const { return p_->incoming.size(); }
std::size_t PeerConnection::pending_bytes() const { return p_->stream->pending_bytes(); }
struct Peer::Impl : std::enable_shared_from_this<Peer::Impl>
{
    runtime::EventLoop& loop; Peer* owner; std::string identity; PeerLimits limits;
    std::shared_ptr<Services> services = std::make_shared<Services>();
    Listener listener; LocalServer local; std::unique_ptr<TlsListener> tls;
    std::optional<Error> configuration_error;
    std::map<std::uint64_t, std::shared_ptr<PeerConnection>> links;
    std::uint64_t next_link = 1;
    bool alive = true, closing = false;
    Impl(runtime::EventLoop& event_loop, Peer* parent, std::string name, PeerLimits options)
        : loop(event_loop), owner(parent), identity(std::move(name)), limits(options), listener(event_loop), local(event_loop)
    { auto valid = validate(identity, limits); if (!valid) configuration_error = valid.error(); }
    Result<void> available() const
    {
        if (configuration_error) return std::unexpected(*configuration_error);
        if (!alive || closing) return reject(ErrorCode::closed, "Peer node is closing");
        return {};
    }
    Result<void> capacity()
    {
        auto valid = available(); if (!valid) return valid;
        std::erase_if(links, [](const auto& item) { return item.second->state() == PeerState::closed || item.second->state() == PeerState::failed; });
        if (links.size() >= limits.connections || next_link == std::numeric_limits<std::uint64_t>::max())
            return reject(ErrorCode::would_block, "Peer connection bound reached");
        return {};
    }
    Result<std::shared_ptr<PeerConnection>> attach(std::unique_ptr<ByteStream> stream)
    {
        auto valid = capacity(); if (!valid) return std::unexpected(valid.error());
        if (!stream || has_callbacks(*stream) || (stream->state() != SocketState::connected && stream->state() != SocketState::connecting))
            return reject(ErrorCode::invalid_argument, "Peer requires a connected/connecting callback-free stream");
        auto session = SessionId::generate(); if (!session) return std::unexpected(session.error());
        auto state = std::make_shared<PeerConnection::Impl>(loop, identity, limits, services, std::move(stream), *session);
        auto link = std::shared_ptr<PeerConnection>(new PeerConnection(state)); state->self = link;
        auto key = next_link++; links.emplace(key, link);
        auto weak = weak_from_this(); auto weak_link = std::weak_ptr<PeerConnection>(link);
        state->on_ready = [weak, weak_link]
        { if (auto keep = weak.lock(); keep && keep->alive) if (auto link = weak_link.lock()) { auto callback = keep->owner->connected; if (callback) callback(std::move(link)); } };
        state->on_failed = [weak, weak_link](Error error)
        { if (auto keep = weak.lock(); keep && keep->alive) if (auto link = weak_link.lock()) { auto callback = keep->owner->failed; if (callback) callback(std::move(link), std::move(error)); } };
        state->on_closed = [weak, key] { if (auto keep = weak.lock()) keep->links.erase(key); };
        if (!state->start()) { link->shutdown(false); return reject(ErrorCode::unavailable, "Core peer dispatch admission failed"); }
        return link;
    }
    void stop_listening() { listener.close(); local.close(); tls.reset(); }
    void close(bool notify)
    {
        if (closing) return;
        auto retained = shared_from_this();
        closing = true; stop_listening(); auto active = std::exchange(links, {});
        for (auto& [id, link] : active) link->shutdown(notify && alive);
        closing = false;
    }
};
Peer::Peer(runtime::EventLoop& loop, std::string identity, PeerLimits limits)
    : p_(std::make_shared<Impl>(loop, this, std::move(identity), limits))
{
    auto weak = std::weak_ptr<Impl>(p_);
    p_->listener.accepted = [weak](std::unique_ptr<Tcp> stream) { if (auto keep = weak.lock()) (void)keep->attach(std::move(stream)); };
    p_->local.accepted = [weak](std::unique_ptr<LocalSocket> stream) { if (auto keep = weak.lock()) (void)keep->attach(std::move(stream)); };
}
Peer::~Peer()
{
    p_->alive = false; p_->services->alive = false; p_->close(false);
    p_->services->operations.clear(); p_->services->authorize = {};
}
Result<void> Peer::expose(std::string operation, Handler handler)
{
    auto valid = p_->available(); if (!valid) return valid;
    if (!name_valid(operation) || !handler) return reject(ErrorCode::invalid_argument, "Invalid peer operation or handler");
    if (p_->services->operations.contains(operation)) return reject(ErrorCode::invalid_state, "Peer operation already exposed");
    if (p_->services->operations.size() >= p_->limits.operations) return reject(ErrorCode::too_large, "Peer operation bound reached");
    p_->services->operations.emplace(std::move(operation), std::move(handler)); return {};
}
bool Peer::remove_operation(std::string_view operation) { return p_->services->operations.erase(std::string(operation)) != 0; }
void Peer::authorize(Authorizer authorize) { p_->services->authorize = std::move(authorize); }
Result<void> Peer::listen(IpEndpoint endpoint, ListenerOptions options)
{ auto valid = p_->available(); if (!valid) return valid; return p_->listener.listen(endpoint, std::move(options)); }
Result<void> Peer::listen_local(LocalEndpoint endpoint, LocalServerOptions options)
{ auto valid = p_->available(); if (!valid) return valid; return p_->local.listen(std::move(endpoint), options); }
Result<void> Peer::listen_tls(IpEndpoint endpoint, std::shared_ptr<TlsContext> context, TlsStreamOptions options)
{
    auto valid = p_->available(); if (!valid) return valid;
    auto listener = std::make_unique<TlsListener>(p_->loop, std::move(context), options);
    auto weak = std::weak_ptr<Impl>(p_);
    listener->accepted = [weak](std::unique_ptr<TlsStream> stream) { if (auto keep = weak.lock()) (void)keep->attach(std::move(stream)); };
    // Replace the TLS acceptor before binding its replacement to the same endpoint.
    p_->tls.reset(); auto result = listener->listen(endpoint); if (!result) return result;
    p_->tls = std::move(listener); return {};
}
Result<std::shared_ptr<PeerConnection>> Peer::connect(IpEndpoint endpoint, TcpOptions options)
{
    auto valid = p_->capacity(); if (!valid) return std::unexpected(valid.error());
    auto stream = std::make_unique<Tcp>(p_->loop); auto result = stream->connect(endpoint, std::move(options));
    if (!result) return std::unexpected(result.error()); return p_->attach(std::move(stream));
}
Result<std::shared_ptr<PeerConnection>> Peer::connect_local(LocalEndpoint endpoint, StreamOptions options)
{
    auto valid = p_->capacity(); if (!valid) return std::unexpected(valid.error());
    auto stream = std::make_unique<LocalSocket>(p_->loop); auto result = stream->connect(std::move(endpoint), options);
    if (!result) return std::unexpected(result.error()); return p_->attach(std::move(stream));
}
Result<std::shared_ptr<PeerConnection>> Peer::connect_tls(IpEndpoint endpoint, std::string name,
    std::shared_ptr<TlsContext> context, TlsStreamOptions options, TcpOptions tcp_options)
{
    auto valid = p_->capacity(); if (!valid) return std::unexpected(valid.error());
    auto stream = std::make_unique<TlsStream>(p_->loop, std::move(context), options); auto result = stream->connect(endpoint, std::move(name), std::move(tcp_options));
    if (!result) return std::unexpected(result.error()); return p_->attach(std::move(stream));
}
Result<std::shared_ptr<PeerConnection>> Peer::attach(std::unique_ptr<ByteStream> stream) { return p_->attach(std::move(stream)); }
void Peer::stop_listening() { p_->stop_listening(); }
void Peer::close() { p_->close(true); }
std::string Peer::identity() const { return p_->identity; }
std::uint16_t Peer::port() const { return p_->listener.port(); }
std::uint16_t Peer::tls_port() const { return p_->tls ? p_->tls->port() : 0; }
std::string Peer::local_path() const { return p_->local.path(); }
std::vector<std::shared_ptr<PeerConnection>> Peer::connections() const
{
    std::vector<std::shared_ptr<PeerConnection>> result;
    for (const auto& [id, link] : p_->links) if (link->state() != PeerState::closed && link->state() != PeerState::failed) result.push_back(link);
    return result;
}
} // namespace ii::network
