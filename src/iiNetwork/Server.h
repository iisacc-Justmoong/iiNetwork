#pragma once
#include <iiNetwork/Application.h>
#include <iiNetwork/Tls.h>
#include <iiNetwork/Local.h>

namespace ii::network
{
struct ServerLimits final
{
    std::size_t connections = 64, header_bytes = 16 * 1024, body_bytes = 2 * 1024 * 1024;
    std::size_t response_bytes = 2 * 1024 * 1024;
    std::chrono::milliseconds request_timeout{10000};
    std::chrono::milliseconds response_timeout{10000};
};
// Native HTTP/1.0 and HTTP/1.1, one request per connection, Content-Length framing.
// HTTP parsing is shared by TCP, TLS and local transports.
class HttpServer final
{
  public:
    using Handler = std::function<ServerResponse(const ServerRequest&)>;
    explicit HttpServer(runtime::EventLoop&);
    ~HttpServer();
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    bool listen(std::string_view address, std::uint16_t port, Handler, ServerLimits = {});
    bool listen(IpEndpoint, Handler, ServerLimits = {}, ListenerOptions = {});
    bool listen_tls(IpEndpoint, std::shared_ptr<TlsContext>, Handler, ServerLimits = {}, TlsStreamOptions = {});
    bool listen_local(LocalEndpoint, Handler, ServerLimits = {}, LocalServerOptions = {});
    // Stop accepting, finish admitted requests, and force close at the deadline.
    // Nonblocking and idempotent; the host must continue dispatching its loop.
    Result<void> shutdown(std::chrono::milliseconds grace = std::chrono::seconds(5));
    void close();
    [[nodiscard]] bool listening() const;
    [[nodiscard]] bool draining() const;
    [[nodiscard]] std::uint16_t port() const;
    [[nodiscard]] std::size_t active_connections() const;
    [[nodiscard]] std::string error() const;
    [[nodiscard]] std::string local_path() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
struct GraphQLExecutionResult final
{
    std::optional<core::Value> data;
    std::vector<GraphQLError> errors;
    core::Value::Object extensions;
};
// The application supplies schema validation, authorization and resolvers.
// This adapter owns POST JSON protocol decoding and response serialization.
class GraphQLService final
{
  public:
    using Executor = std::function<GraphQLExecutionResult(const GraphQLRequest&)>;
    explicit GraphQLService(Executor, std::size_t maximum_bytes = 2 * 1024 * 1024);
    ServerResponse operator()(const ServerRequest&) const;
  private:
    Executor execute_;
    std::size_t limit_;
};
} // namespace ii::network
