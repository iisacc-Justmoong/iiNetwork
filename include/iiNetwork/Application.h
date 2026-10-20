#pragma once
#include <iiNetwork/Error.h>
#include <iiNetwork/Http.h>
#include <iiJson/Json.h>
#include <iiNetwork/ByteStream.h>
#include <optional>
#include <utility>

namespace ii::network
{
class HttpTransport
{
  public:
    virtual ~HttpTransport() = default;
    // false: request not admitted, callback will not run. cancel suppresses completion.
    virtual bool start(HttpRequest, std::function<void(HttpResponse)>) = 0;
    virtual void cancel() = 0;
    [[nodiscard]] virtual bool busy() const = 0;
};
class NativeHttpTransport final : public HttpTransport
{
  public:
    explicit NativeHttpTransport(runtime::EventLoop& loop) : http_(loop) {}
    bool start(HttpRequest, std::function<void(HttpResponse)>) override;
    void cancel() override;
    [[nodiscard]] bool busy() const override;
  private:
    Http http_;
};
struct RequestOptions final
{
    std::map<std::string, std::string> headers;
    std::chrono::milliseconds timeout{10000};
    std::size_t maximum_bytes = 2 * 1024 * 1024;
};
struct RestRequest final
{
    std::string method = "GET", path;
    std::vector<std::pair<std::string, std::string>> query;
    std::optional<core::Value> json;
    std::optional<std::string> body; // mutually exclusive with json; media type is a caller header
    bool parse_json_response = true;
    RequestOptions options;
};
struct RestResponse final
{
    HttpResponse http;
    std::optional<core::Value> json;
    std::optional<Error> error;
    [[nodiscard]] bool ok() const;
};
class RestClient final
{
  public:
    RestClient(HttpTransport& transport, std::string base_url);
    Result<HttpRequest> prepare(const RestRequest&) const;
    bool request(RestRequest, std::function<void(RestResponse)>);
    void cancel();
  private:
    HttpTransport& transport_;
    std::string base_url_;
};
struct GraphQLRequest final
{
    std::string query, operation_name;
    core::Value::Object variables, extensions;
    RequestOptions options;
};
struct GraphQLError final
{
    std::string message;
    core::Value::Array locations, path;
    core::Value::Object extensions;
};
struct GraphQLResponse final
{
    HttpResponse http;
    std::optional<core::Value> data; // explicit JSON null remains distinct from absence
    std::vector<GraphQLError> errors;
    core::Value::Object extensions;
    std::optional<Error> error; // transport/HTTP/envelope failure, separate from execution errors
    [[nodiscard]] bool ok() const;
};
class GraphQLClient final
{
  public:
    GraphQLClient(HttpTransport&, std::string endpoint);
    Result<HttpRequest> prepare(const GraphQLRequest&) const;
    bool execute(GraphQLRequest, std::function<void(GraphQLResponse)>);
    void cancel();
    static GraphQLResponse decode(HttpResponse, std::size_t limit = 2 * 1024 * 1024);
  private:
    HttpTransport& transport_;
    std::string endpoint_;
};
struct ServerRequest final
{
    std::string method = "GET", target = "/", body;
    std::map<std::string, std::string> headers;
    std::optional<IpEndpoint> peer_endpoint, local_endpoint;
    std::optional<PeerCredentials> local_peer;
    bool secure = false;
    std::optional<CertificateInfo> peer_certificate;
};
struct ServerResponse final
{
    unsigned status = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    HeaderFields header_fields{};
};
class HttpRouter final
{
  public:
    using Parameters = std::map<std::string, std::string>;
    using Handler = std::function<ServerResponse(const ServerRequest&, const Parameters&)>;
    Result<void> add(std::string method, std::string pattern, Handler);
    ServerResponse dispatch(const ServerRequest&) const;
  private:
    struct Entry { std::string method, pattern; std::vector<std::string> segments; Handler handler; };
    std::vector<Entry> entries_;
};
class ApplicationLayer final
{
  public:
    static constexpr Layer layer = Layer::application;
    explicit ApplicationLayer(runtime::EventLoop& loop) : loop_(loop) {}
    HttpRouter router;
    [[nodiscard]] std::unique_ptr<NativeHttpTransport> http() const;
    [[nodiscard]] RestClient rest(HttpTransport&, std::string base_url) const;
    [[nodiscard]] GraphQLClient graphql(HttpTransport&, std::string endpoint) const;
  private:
    runtime::EventLoop& loop_;
};
} // namespace ii::network
