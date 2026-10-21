#pragma once
#include <iiNetwork/Security.h>
#include <iiNetwork/Transport.h>

namespace ii::network
{
enum class TlsRole { client, server };
enum class TlsState { idle, connecting, handshaking, secured, closing, closed, failed };
struct TlsOptions final
{
    TlsPolicy policy;
    std::vector<std::string> alpn_protocols;
    bool require_client_certificate = false;
    int verification_depth = 8;
};
struct TlsConnectionInfo final
{
    std::string protocol, cipher, alpn, server_name;
    bool peer_verified = false, session_reused = false;
    std::optional<CertificateInfo> peer_certificate;
};
class TlsContext final
{
  public:
    static Result<std::shared_ptr<TlsContext>> client(TlsOptions = {});
    static Result<std::shared_ptr<TlsContext>> server(TlsOptions);
    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    [[nodiscard]] TlsRole role() const;
  private:
    friend class TlsStream;
    struct Impl;
    explicit TlsContext(std::shared_ptr<Impl>);
    static Result<std::shared_ptr<TlsContext>> create(TlsRole, TlsOptions);
    std::shared_ptr<Impl> p_;
};
struct TlsStreamOptions final
{
    std::chrono::milliseconds handshake_timeout{10000};
    std::size_t receive_bytes = 2 * 1024 * 1024, pending_bytes = 2 * 1024 * 1024;
    std::size_t cipher_bytes = 4 * 1024 * 1024;
};
class TlsStream final : public ByteStream
{
  public:
    TlsStream(runtime::EventLoop&, std::shared_ptr<TlsContext>, TlsStreamOptions = {});
    ~TlsStream() override;
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;
    Result<void> connect(IpEndpoint, std::string server_name, TcpOptions = {});
    // Takes a connected callback-free stream (TCP or local). Handshake starts on the loop.
    Result<void> attach(std::unique_ptr<ByteStream>, std::string server_name = {});
    using ByteStream::write;
    bool write(std::string_view) override;
    std::string read() override;
    std::string read_some(std::size_t) override;
    std::string peek(std::size_t maximum = std::numeric_limits<std::size_t>::max()) const override;
    std::size_t available_bytes() const override;
    std::size_t pending_bytes() const override;
    void receive_limit(std::size_t) override;
    void send_limit(std::size_t) override;
    void close(bool flush = false) override;
    bool is_connected() const override;
    SocketState state() const override;
    std::string error() const override;
    StreamStatistics statistics() const override;
    std::optional<IpEndpoint> local_endpoint() const override;
    std::optional<IpEndpoint> peer_endpoint() const override;
    std::optional<PeerCredentials> peer_credentials() const override;
    [[nodiscard]] TlsState tls_state() const;
    [[nodiscard]] std::optional<TlsConnectionInfo> connection_info() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
    Result<void> prepare(std::unique_ptr<ByteStream>, std::string, bool connecting);
};
class TlsListener final
{
  public:
    TlsListener(runtime::EventLoop&, std::shared_ptr<TlsContext>, TlsStreamOptions = {});
    ~TlsListener();
    TlsListener(const TlsListener&) = delete;
    TlsListener& operator=(const TlsListener&) = delete;
    // Accepted streams are handshaking; their connected callback means TLS is secured.
    std::function<void(std::unique_ptr<TlsStream>)> accepted;
    std::function<void(std::string)> failed;
    Result<void> listen(IpEndpoint, ListenerOptions = {});
    void close();
    [[nodiscard]] std::uint16_t port() const;
    [[nodiscard]] std::string error() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
