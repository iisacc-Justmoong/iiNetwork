#include <iiNetwork/Server.h>
#include <iiNetwork/Transport.h>
#include <iiNetwork/Wire.h>
#include "HttpInternal.h"
#include <algorithm>
#include <charconv>
#include <limits>

namespace ii::network
{
namespace
{
std::string trim_http(std::string_view text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return std::string(text);
}
std::optional<std::string> header(const ServerRequest& request, std::string_view key)
{
    for (const auto& [name, value] : request.headers) if (wire::lower(name) == key) return value;
    return {};
}
std::string media_type(std::string_view value)
{ return wire::lower(trim_http(value.substr(0, value.find(';')))); }
ServerResponse graphql_error(unsigned status, std::string message, std::string media = "application/graphql-response+json")
{
    auto body = ii::json::stringify(core::Value(core::Value::Object{
        {"errors", core::Value(core::Value::Array{core::Value(core::Value::Object{{"message", core::Value(std::move(message))}})})}}));
    return {status, {{"Content-Type", std::move(media)}}, body ? std::move(*body) : std::string{}};
}
}
struct HttpServer::Impl : std::enable_shared_from_this<HttpServer::Impl>
{
    struct Connection
    {
        std::size_t id;
        std::unique_ptr<ByteStream> socket;
        runtime::TaskToken deadline;
        runtime::Clock::time_point expires;
        std::string buffer;
        ServerRequest request;
        std::size_t expected_body = 0;
        bool headers_done = false, responding = false;
        Connection(std::size_t key, std::unique_ptr<ByteStream> stream) : id(key), socket(std::move(stream)) {}
        ~Connection() { deadline.cancel(); }
    };
    runtime::EventLoop& loop;
    Listener listener;
    std::unique_ptr<TlsListener> tls_listener;
    std::unique_ptr<LocalServer> local_listener;
    bool secure = false;
    Handler handle;
    ServerLimits limits;
    std::map<std::size_t, std::shared_ptr<Connection>> connections;
    std::size_t next_id = 0;
    bool listening = false, draining = false;
    runtime::TaskToken shutdown_deadline;
    std::string error;
    explicit Impl(runtime::EventLoop& event_loop) : loop(event_loop), listener(event_loop) {}
    void stop_accepting()
    {
        listening = false; listener.accepted = {}; listener.close();
        tls_listener.reset(); local_listener.reset(); secure = false;
    }
    void close()
    {
        stop_accepting(); draining = false; shutdown_deadline.cancel();
        for (auto& [id, connection] : connections)
        {
            connection->deadline.cancel();
            connection->socket->readable = {}; connection->socket->disconnected = {}; connection->socket->failed = {};
            connection->socket->close();
        }
        connections.clear(); handle = {};
    }
    bool configure(Handler handler, ServerLimits value)
    {
        close(); error.clear();
        if (!handler || !value.connections || value.connections > 65536 || value.header_bytes < 16 || !value.response_bytes ||
            value.body_bytes > 512 * 1024 * 1024 || value.response_bytes > 512 * 1024 * 1024 || value.header_bytes > 64 * 1024 ||
            value.request_timeout.count() <= 0 || value.request_timeout > std::chrono::hours(24 * 365) ||
            value.response_timeout.count() <= 0 || value.response_timeout > std::chrono::hours(24 * 365))
        { error = "Invalid HTTP server limits or handler"; return false; }
        limits = value; handle = std::move(handler); return true;
    }
    void remove(std::size_t id)
    {
        auto found = connections.find(id); if (found == connections.end()) return;
        found->second->deadline.cancel(); connections.erase(found);
        if (connections.empty() && draining)
        { draining = false; shutdown_deadline.cancel(); handle = {}; }
    }
    void respond(const std::shared_ptr<Connection>& connection, ServerResponse response)
    {
        if ((!listening && !draining) || !connections.contains(connection->id) || connection->responding) return;
        connection->responding = true; connection->deadline.cancel();
        connection->socket->readable = {};
        bool invalid = response.status < 200 || response.status > 599 || response.body.size() > limits.response_bytes || response.headers.size() + response.header_fields.size() > 128;
        std::size_t header_bytes = 0;
        for (const auto& [key, value] : response.headers)
        {
            if (!detail::token(key) || !detail::header_value(value) || key.size() > 8192 || value.size() > 65536) invalid = true;
            header_bytes += key.size() + value.size();
            if (header_bytes > 65536) invalid = true;
        }
        for (const auto& [key, value] : response.header_fields.entries())
        { header_bytes += key.size() + value.size(); if (header_bytes > 65536) invalid = true; }
        if (invalid)
        {
            response = {500, {}, "Invalid or oversized server response"};
            response.body.resize(std::min(response.body.size(), limits.response_bytes));
        }
        if (response.status == 204 || response.status == 304) response.body.clear();
        std::string bytes = "HTTP/1.1 " + std::to_string(response.status) + " Response\r\nConnection: close\r\n";
        for (const auto& [key, value] : response.headers)
        {
            auto lower = wire::lower(key);
            if (lower != "content-length" && lower != "transfer-encoding" && lower != "connection") bytes += key + ": " + value + "\r\n";
        }
        for (const auto& [key, value] : response.header_fields.entries())
        {
            auto lower = wire::lower(key);
            if (lower != "content-length" && lower != "transfer-encoding" && lower != "connection") bytes += key + ": " + value + "\r\n";
        }
        if (response.status != 204 && response.status != 304)
            bytes += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
        bytes += "\r\n";
        if (connection->request.method != "HEAD") bytes += response.body;
        connection->socket->send_limit(bytes.size());
        connection->deadline = loop.after(limits.response_timeout,
            [weak = weak_from_this(), client = std::weak_ptr<Connection>(connection)] {
                const auto keep = weak.lock(); const auto c = client.lock();
                if (keep && c) { c->socket->close(); keep->remove(c->id); }
            }).token;
        if (!connection->deadline.pending()) { connection->socket->close(); remove(connection->id); return; }
        if (!connection->socket->write(bytes)) { connection->socket->close(); remove(connection->id); return; }
        connection->socket->close(true);
    }
    void reject(const std::shared_ptr<Connection>& connection, unsigned status, std::string message)
    { respond(connection, {status, {{"Content-Type", "text/plain; charset=utf-8"}}, std::move(message)}); }
    void read(const std::shared_ptr<Connection>& connection)
    {
        if ((!listening && !draining) || connection->responding) return;
        if (runtime::Clock::now() >= connection->expires) { reject(connection, 408, "Request deadline elapsed"); return; }
        connection->buffer += connection->socket->read();
        auto& bytes = connection->buffer;
        if (!connection->headers_done)
        {
            auto end = bytes.find("\r\n\r\n");
            if (end == bytes.npos)
            { if (bytes.size() > limits.header_bytes) reject(connection, 431, "Request headers too large"); return; }
            if (end + 4 > limits.header_bytes) { reject(connection, 431, "Request headers too large"); return; }
            auto first = bytes.find("\r\n");
            std::string_view line(bytes.data(), first);
            auto method_end = line.find(' '), target_end = line.find(' ', method_end == line.npos ? 0 : method_end + 1);
            if (method_end == line.npos || target_end == line.npos || target_end == method_end + 1 ||
                !detail::token(line.substr(0, method_end))) { reject(connection, 400, "Invalid request line"); return; }
            auto version = line.substr(target_end + 1);
            if (version != "HTTP/1.1" && version != "HTTP/1.0") { reject(connection, 505, "Unsupported HTTP version"); return; }
            connection->request.method = line.substr(0, method_end);
            connection->request.target = line.substr(method_end + 1, target_end - method_end - 1);
            for (unsigned char c : connection->request.target)
                if (c <= 32 || c == 127) { reject(connection, 400, "Invalid request target"); return; }
            if (!connection->request.target.starts_with('/') || connection->request.target.starts_with("//") ||
                connection->request.target.find('#') != std::string::npos)
            { reject(connection, 400, "Expected origin-form target"); return; }
            auto& headers = connection->request.headers;
            for (auto offset = first + 2; offset < end;)
            {
                auto next = bytes.find("\r\n", offset);
                std::string_view field(bytes.data() + offset, next - offset);
                auto colon = field.find(':');
                if (colon == field.npos || !detail::token(field.substr(0, colon)) || !detail::header_value(field.substr(colon + 1)))
                { reject(connection, 400, "Invalid HTTP header"); return; }
                auto key = wire::lower(std::string(field.substr(0, colon))), value = trim_http(field.substr(colon + 1));
                auto existing = headers.find(key);
                if (existing != headers.end())
                {
                    if (key == "content-length" || key == "host" || key == "transfer-encoding")
                    { reject(connection, 400, "Duplicate framing or authority header"); return; }
                    existing->second += (key == "cookie" ? "; " : ", ") + value;
                }
                else headers.emplace(std::move(key), std::move(value));
                if (headers.size() > 128) { reject(connection, 431, "Too many HTTP headers"); return; }
                offset = next + 2;
            }
            if (version == "HTTP/1.1" && (!headers.contains("host") || headers.at("host").empty()))
            { reject(connection, 400, "HTTP/1.1 requires Host"); return; }
            if (auto host = headers.find("host"); host != headers.end() &&
                (host->second.find_first_of("/?#@\\") != std::string::npos || !detail::http_url("http://" + host->second + '/')))
            { reject(connection, 400, "Invalid Host authority"); return; }
            if (headers.contains("transfer-encoding"))
            { reject(connection, headers.contains("content-length") ? 400 : 501, "Transfer coding is not supported"); return; }
            if (auto length = headers.find("content-length"); length != headers.end())
            {
                const auto& text = length->second;
                auto [last, error] = std::from_chars(text.data(), text.data() + text.size(), connection->expected_body);
                if (text.empty() || error != std::errc{} || last != text.data() + text.size())
                { reject(connection, 400, "Invalid Content-Length"); return; }
                if (connection->expected_body > limits.body_bytes) { reject(connection, 413, "Request body too large"); return; }
            }
            if (headers.contains("expect")) { reject(connection, 417, "Expect is not supported"); return; }
            connection->headers_done = true; bytes.erase(0, end + 4);
        }
        if (bytes.size() > connection->expected_body) { reject(connection, 400, "Extra request bytes or pipelining"); return; }
        if (bytes.size() < connection->expected_body) return;
        connection->request.body = std::move(bytes);
        connection->request.peer_endpoint = connection->socket->peer_endpoint();
        connection->request.local_endpoint = connection->socket->local_endpoint();
        connection->request.local_peer = connection->socket->peer_credentials();
        if (auto* tls = dynamic_cast<TlsStream*>(connection->socket.get()))
            if (auto info = tls->connection_info()) connection->request.peer_certificate = info->peer_certificate;
        auto handler = handle;
        ServerResponse response;
        try { response = handler(connection->request); }
        catch (...) { response = {500, {}, "Request handler failed"}; }
        if (listening || draining) respond(connection, std::move(response));
    }
    void accept(std::unique_ptr<ByteStream> socket)
    {
        if (!listening || connections.size() >= limits.connections) { socket->close(); return; }
        auto connection = std::make_shared<Connection>(next_id++, std::move(socket));
        connection->request.secure = secure;
        connection->expires = runtime::Clock::now() + limits.request_timeout;
        connections.emplace(connection->id, connection);
        // Leave room for one transport read even when HTTP limits are tiny.
        // The parser still rejects oversized headers/bodies before dispatch.
        connection->socket->receive_limit(std::max<std::size_t>(65536, limits.header_bytes + limits.body_bytes));
        auto weak = weak_from_this(); auto client = std::weak_ptr<Connection>(connection); auto id = connection->id;
        connection->socket->readable = [weak, client]
        { auto keep = weak.lock(); auto c = client.lock(); if (keep && c) keep->read(c); };
        connection->socket->failed = [weak, id](std::string) { if (auto keep = weak.lock()) keep->remove(id); };
        connection->socket->disconnected = [weak, id] { if (auto keep = weak.lock()) keep->remove(id); };
        connection->deadline = loop.after(limits.request_timeout, [weak, client]
        { auto keep = weak.lock(); auto c = client.lock(); if (keep && c) keep->reject(c, 408, "Request deadline elapsed"); }).token;
        if (!connection->deadline.pending()) { connection->socket->close(); remove(id); }
    }
};
HttpServer::HttpServer(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop)) {}
HttpServer::~HttpServer() { close(); }
bool HttpServer::listen(std::string_view address, std::uint16_t port, Handler handler, ServerLimits limits)
{
    auto ip = IpAddress::parse(address);
    if (!ip) { p_->error = ip.error().message; return false; }
    return listen(IpEndpoint{*ip, port}, std::move(handler), limits);
}
bool HttpServer::listen(IpEndpoint endpoint, Handler handler, ServerLimits limits, ListenerOptions options)
{
    auto& p = *p_; if (!p.configure(std::move(handler), limits)) return false;
    p.listener.accepted = [weak = std::weak_ptr<Impl>(p_)](std::unique_ptr<Tcp> socket)
    { if (auto keep = weak.lock()) keep->accept(std::move(socket)); };
    auto result = p.listener.listen(endpoint, std::move(options));
    if (!result) { p.error = result.error().message; p.close(); return false; }
    p.listening = true; return true;
}
bool HttpServer::listen_tls(IpEndpoint endpoint, std::shared_ptr<TlsContext> context, Handler handler, ServerLimits limits, TlsStreamOptions options)
{
    auto& p = *p_; if (!p.configure(std::move(handler), limits)) return false;
    p.secure = true; p.tls_listener = std::make_unique<TlsListener>(p.loop, std::move(context), options);
    p.tls_listener->accepted = [weak = std::weak_ptr<Impl>(p_)](std::unique_ptr<TlsStream> socket)
    { if (auto keep = weak.lock()) keep->accept(std::move(socket)); };
    auto result = p.tls_listener->listen(endpoint);
    if (!result) { p.error = result.error().message; p.close(); return false; }
    p.listening = true; return true;
}
bool HttpServer::listen_local(LocalEndpoint endpoint, Handler handler, ServerLimits limits, LocalServerOptions options)
{
    auto& p = *p_; if (!p.configure(std::move(handler), limits)) return false;
    p.local_listener = std::make_unique<LocalServer>(p.loop);
    p.local_listener->accepted = [weak = std::weak_ptr<Impl>(p_)](std::unique_ptr<LocalSocket> socket)
    { if (auto keep = weak.lock()) keep->accept(std::move(socket)); };
    auto result = p.local_listener->listen(std::move(endpoint), options);
    if (!result) { p.error = result.error().message; p.close(); return false; }
    p.listening = true; return true;
}
void HttpServer::close() { p_->close(); }
Result<void> HttpServer::shutdown(std::chrono::milliseconds grace)
{
    if (grace.count() < 0 || grace > std::chrono::hours(24))
        return detail::fail(Layer::application, ErrorCode::invalid_argument, "Invalid HTTP shutdown grace period");
    auto& p = *p_;
    if (p.draining) return {};
    p.stop_accepting();
    if (p.connections.empty()) { p.handle = {}; return {}; }
    if (grace.count() == 0) { p.close(); return {}; }
    p.draining = true;
    p.shutdown_deadline = p.loop.after(grace, [weak = std::weak_ptr<Impl>(p_)] {
        if (const auto keep = weak.lock()) keep->close();
    }).token;
    if (!p.shutdown_deadline.pending())
    {
        p.error = "Core HTTP shutdown dispatch admission failed"; p.close();
        return detail::fail(Layer::application, ErrorCode::unavailable, p.error);
    }
    return {};
}
bool HttpServer::listening() const { return p_->listening; }
bool HttpServer::draining() const { return p_->draining; }
std::uint16_t HttpServer::port() const { return p_->tls_listener ? p_->tls_listener->port() : p_->listener.port(); }
std::size_t HttpServer::active_connections() const { return p_->connections.size(); }
std::string HttpServer::error() const { return p_->error; }
std::string HttpServer::local_path() const { return p_->local_listener ? p_->local_listener->path() : std::string{}; }
GraphQLService::GraphQLService(Executor execute, std::size_t limit) : execute_(std::move(execute)), limit_(limit) {}
ServerResponse GraphQLService::operator()(const ServerRequest& request) const
{
    if (request.method != "POST")
    { auto result = graphql_error(405, "GraphQL endpoint requires POST"); result.headers.emplace("Allow", "POST"); return result; }
    auto type = header(request, "content-type");
    if (!type || media_type(*type) != "application/json") return graphql_error(415, "GraphQL request requires application/json");
    if (request.body.size() > limit_) return graphql_error(413, "GraphQL request too large");
    ii::json::Limits limits; limits.input_bytes = limits.output_bytes = limit_;
    auto tree = ii::json::parse(request.body, limits);
    if (!tree || !tree->get<core::Value::Object>()) return graphql_error(400, "GraphQL request must be a JSON object");
    const auto& object = tree->get<core::Value::Object>()->get();
    auto query = object.find("query");
    if (query == object.end() || !query->second.get<std::string>() || wire::trim(query->second.get<std::string>()->get()).empty())
        return graphql_error(400, "GraphQL query must be a nonempty string");
    GraphQLRequest operation; operation.query = query->second.get<std::string>()->get();
    operation.options.headers = request.headers;
    operation.options.maximum_bytes = limit_;
    for (const auto& [key, value] : object)
    {
        if (value == core::Value{}) continue; // optional fields may be explicit JSON null
        if (key == "operationName")
        {
            auto name = value.get<std::string>(); if (!name) return graphql_error(400, "operationName must be a string");
            operation.operation_name = name->get();
        }
        else if (key == "variables" || key == "extensions")
        {
            auto fields = value.get<core::Value::Object>();
            if (!fields) return graphql_error(400, "variables and extensions must be objects");
            (key == "variables" ? operation.variables : operation.extensions) = fields->get();
        }
    }
    if (!execute_) return graphql_error(500, "GraphQL executor is unavailable");
    GraphQLExecutionResult result;
    try { result = execute_(operation); }
    catch (...) { return graphql_error(500, "GraphQL execution failed"); }
    if ((!result.data && result.errors.empty()) ||
        (result.data && !result.data->get<core::Value::Object>() && *result.data != core::Value{}))
        return graphql_error(500, "Invalid GraphQL execution result");
    core::Value::Object envelope;
    if (result.data) envelope.emplace("data", *result.data);
    if (!result.errors.empty())
    {
        core::Value::Array errors;
        for (const auto& error : result.errors)
        {
            core::Value::Object item{{"message", core::Value(error.message)}};
            if (!error.path.empty()) item.emplace("path", core::Value(error.path));
            if (!error.locations.empty()) item.emplace("locations", core::Value(error.locations));
            if (!error.extensions.empty()) item.emplace("extensions", core::Value(error.extensions));
            errors.emplace_back(std::move(item));
        }
        envelope.emplace("errors", core::Value(std::move(errors)));
    }
    if (!result.extensions.empty()) envelope.emplace("extensions", core::Value(std::move(result.extensions)));
    auto body = ii::json::stringify(core::Value(std::move(envelope)), limits);
    if (!body) return graphql_error(500, "GraphQL response serialization failed");
    HttpResponse check; check.status = 200; check.body = *body;
    if (GraphQLClient::decode(std::move(check), limit_).error) return graphql_error(500, "Invalid GraphQL execution error metadata");
    auto accept = header(request, "accept");
    auto media = accept && accept->find("application/graphql-response+json") != accept->npos
        ? "application/graphql-response+json" : "application/json";
    return {200, {{"Content-Type", media}}, std::move(*body)};
}
} // namespace ii::network
