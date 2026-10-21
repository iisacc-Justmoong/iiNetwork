#pragma once
#include <iiNetwork/Local.h>
#include <iiNetwork/Session.h>
#include <iiNetwork/Tls.h>
#include <iiSDKCore/Core/Value/Value.h>

namespace ii::network
{
class PeerConnection;
enum class PeerState { connecting, negotiating, ready, closed, failed };
struct PeerLimits final
{
    std::size_t frame_bytes = 1024 * 1024, pending_bytes = 2 * 1024 * 1024;
    std::size_t connections = 64, requests = 64, operations = 128;
    std::chrono::milliseconds handshake_timeout{10000}, maximum_call_timeout{60000};
};
struct PeerInfo final
{
    std::string identity; // Remote claim; transport evidence does not bind this name.
    SessionId local_session, remote_session;
    std::optional<IpEndpoint> local_endpoint, remote_endpoint;
    std::optional<PeerCredentials> local_credentials;
    std::optional<TlsConnectionInfo> tls;
};
struct PeerEvent final { std::string topic; core::Value value; };
struct PeerCall final
{
    std::uint64_t id;
    std::string operation;
    core::Value arguments;
    std::shared_ptr<PeerConnection> connection;
};
// Copyable deferred response, confined to its owning loop. A late/double reply fails.
class PeerReply final
{
  public:
    PeerReply() = default;
    Result<void> operator()(Result<core::Value>) const;
    [[nodiscard]] bool pending() const;
    [[nodiscard]] bool cancelled() const;
  private:
    friend class PeerConnection;
    struct State;
    explicit PeerReply(std::shared_ptr<State>);
    std::shared_ptr<State> p_;
};
// Both ends have this exact interface, regardless of who opened the transport.
class PeerConnection final
{
  public:
    using Completion = std::function<void(Result<core::Value>)>;
    ~PeerConnection();
    PeerConnection(const PeerConnection&) = delete;
    PeerConnection& operator=(const PeerConnection&) = delete;
    std::function<void()> connected, disconnected;
    std::function<void(Error)> failed;
    std::function<void(PeerEvent)> received;
    Result<std::uint64_t> request(std::string operation, core::Value arguments, Completion,
                                  std::chrono::milliseconds timeout = std::chrono::seconds(10));
    Result<void> notify(std::string topic, core::Value);
    // Suppresses local completion and sends cooperative remote cancellation.
    bool cancel(std::uint64_t request_id);
    void close();
    [[nodiscard]] PeerState state() const;
    [[nodiscard]] std::optional<PeerInfo> info() const;
    [[nodiscard]] std::optional<Error> error() const;
    [[nodiscard]] std::size_t pending_requests() const;
    [[nodiscard]] std::size_t active_requests() const;
    [[nodiscard]] std::size_t pending_bytes() const;
  private:
    friend class Peer;
    struct Impl;
    explicit PeerConnection(std::shared_ptr<Impl>);
    void shutdown(bool notify);
    std::shared_ptr<Impl> p_;
};
// A node may listen and dial simultaneously; neither action assigns application rank.
class Peer final
{
  public:
    using Handler = std::function<void(PeerCall, PeerReply)>;
    using Authorizer = std::function<bool(const PeerInfo&, std::string_view operation)>;
    Peer(runtime::EventLoop&, std::string identity, PeerLimits = {});
    ~Peer();
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    std::function<void(std::shared_ptr<PeerConnection>)> connected;
    std::function<void(std::shared_ptr<PeerConnection>, Error)> failed;
    Result<void> expose(std::string operation, Handler);
    bool remove_operation(std::string_view operation);
    void authorize(Authorizer);
    Result<void> listen(IpEndpoint, ListenerOptions = {});
    Result<void> listen_tls(IpEndpoint, std::shared_ptr<TlsContext>, TlsStreamOptions = {});
    Result<void> listen_local(LocalEndpoint, LocalServerOptions = {});
    Result<std::shared_ptr<PeerConnection>> connect(IpEndpoint, TcpOptions = {});
    Result<std::shared_ptr<PeerConnection>> connect_tls(IpEndpoint, std::string server_name,
        std::shared_ptr<TlsContext>, TlsStreamOptions = {}, TcpOptions = {});
    Result<std::shared_ptr<PeerConnection>> connect_local(LocalEndpoint, StreamOptions = {});
    // Owns a connected or connecting callback-free TCP/TLS/local/custom stream.
    Result<std::shared_ptr<PeerConnection>> attach(std::unique_ptr<ByteStream>);
    void stop_listening();
    void close();
    [[nodiscard]] std::string identity() const;
    [[nodiscard]] std::uint16_t port() const;
    [[nodiscard]] std::uint16_t tls_port() const;
    [[nodiscard]] std::string local_path() const;
    [[nodiscard]] std::vector<std::shared_ptr<PeerConnection>> connections() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
