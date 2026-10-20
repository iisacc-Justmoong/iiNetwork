#include <iiNetwork/Application.h>
#include <iiNetwork/Wire.h>
#include "HttpInternal.h"
#include <algorithm>
#include <set>

namespace ii::network
{
using detail::fail;
namespace
{
Error application_error(ErrorCode code, std::string message)
{ return {code, Layer::application, std::move(message)}; }
std::optional<Error> response_error(const HttpResponse& http)
{
    if (http.cancelled) return application_error(ErrorCode::closed, "HTTP request cancelled");
    if (http.too_large) return application_error(ErrorCode::too_large, "HTTP response limit exceeded");
    if (!http.error.empty()) return application_error(ErrorCode::io_error, http.error);
    if (http.timed_out) return application_error(ErrorCode::io_error, "HTTP request timed out");
    if (http.status < 200 || http.status >= 300)
        return application_error(ErrorCode::io_error, "HTTP status " + std::to_string(http.status));
    return {};
}
std::string percent_encode(std::string_view bytes)
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned char c : bytes)
    {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') result += static_cast<char>(c);
        else { result += '%'; result += hex[c >> 4]; result += hex[c & 15]; }
    }
    return result;
}
std::vector<std::string> segments(std::string_view path)
{
    std::vector<std::string> result;
    if (path.starts_with('/')) path.remove_prefix(1);
    if (path.empty()) return result;
    for (;;)
    {
        auto slash = path.find('/'); result.emplace_back(path.substr(0, slash));
        if (slash == path.npos) return result;
        path.remove_prefix(slash + 1);
    }
}
void set_header(HttpRequest& request, std::string key, std::string value)
{
    auto lowered = wire::lower(key);
    std::erase_if(request.headers, [&](const auto& pair) { return wire::lower(pair.first) == lowered; });
    request.headers.emplace(std::move(key), std::move(value));
}
bool options(HttpRequest& request, const RequestOptions& options)
{
    request.timeout = options.timeout; request.maximum_bytes = options.maximum_bytes;
    std::set<std::string> keys;
    for (const auto& [key, value] : options.headers)
    {
        auto lower = wire::lower(key);
        if (!detail::token(key) || !detail::header_value(value) || !keys.insert(lower).second ||
            lower == "content-length" || lower == "transfer-encoding") return false;
    }
    request.headers = options.headers;
    return request.timeout.count() > 0 && request.maximum_bytes > 0;
}
bool parameter(std::string_view segment)
{ return segment.size() >= 3 && segment.front() == '{' && segment.back() == '}'; }
bool integer(const core::Value& value, bool positive)
{
    return std::visit([positive](const auto& number)
    {
        using T = std::decay_t<decltype(number)>;
        if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>)
            return positive ? number > 0 : number >= 0;
        return false;
    }, value.storage());
}
}
bool NativeHttpTransport::start(HttpRequest request, std::function<void(HttpResponse)> callback)
{ return http_.start(std::move(request), std::move(callback)); }
void NativeHttpTransport::cancel() { http_.cancel(); }
bool NativeHttpTransport::busy() const { return http_.busy(); }
bool RestResponse::ok() const { return !error && http.status >= 200 && http.status < 300; }
RestClient::RestClient(HttpTransport& transport, std::string base) : transport_(transport), base_url_(std::move(base)) {}
Result<HttpRequest> RestClient::prepare(const RestRequest& input) const
{
    if (input.json && input.body) return fail(Layer::application, ErrorCode::invalid_argument, "REST JSON and raw bodies are mutually exclusive");
    if (!detail::http_url(base_url_) || base_url_.find_first_of("?#") != std::string::npos ||
        input.path.starts_with("//") || input.path.find("://") != std::string::npos ||
        input.path.find('\\') != std::string::npos || input.path.size() > 16384)
        return fail(Layer::application, ErrorCode::invalid_argument, "Invalid REST base URL or relative path");
    HttpRequest request; request.method = input.method; request.url = base_url_;
    if (!options(request, input.options)) return fail(Layer::application, ErrorCode::invalid_argument, "Invalid REST request options");
    while (request.url.ends_with('/')) request.url.pop_back();
    auto parts = segments(input.path);
    request.url += '/';
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (parts[i] == "." || parts[i] == "..") return fail(Layer::application, ErrorCode::invalid_argument, "REST path traversal rejected");
        if (i) request.url += '/';
        request.url += percent_encode(parts[i]);
    }
    if (input.query.size() > 1024) return fail(Layer::application, ErrorCode::too_large, "REST query item limit exceeded");
    for (std::size_t i = 0; i < input.query.size(); ++i)
    {
        request.url += i ? '&' : '?'; request.url += percent_encode(input.query[i].first);
        request.url += '='; request.url += percent_encode(input.query[i].second);
        if (request.url.size() > 65536) return fail(Layer::application, ErrorCode::too_large, "REST URL limit exceeded");
    }
    if (input.json)
    {
        auto serialized = ii::json::stringify(*input.json);
        if (!serialized) return fail(Layer::application, ErrorCode::malformed, serialized.error().message);
        request.body = std::move(*serialized); set_header(request, "Content-Type", "application/json");
    }
    else if (input.body) request.body = *input.body;
    // Preserve an explicit caller Accept header; JSON is the default.
    if (input.parse_json_response && std::none_of(request.headers.begin(), request.headers.end(), [](const auto& h) { return wire::lower(h.first) == "accept"; }))
        request.headers.emplace("Accept", "application/json");
    if (!detail::http_request(request)) return fail(Layer::application, ErrorCode::invalid_argument, "Invalid REST HTTP request");
    return request;
}
bool RestClient::request(RestRequest input, std::function<void(RestResponse)> callback)
{
    if (!callback) return false;
    auto request = prepare(input); if (!request) return false;
    auto limit = request->maximum_bytes;
    return transport_.start(std::move(*request), [callback = std::move(callback), limit, parse_json = input.parse_json_response](HttpResponse http)
    {
        RestResponse response; response.http = std::move(http); response.error = response_error(response.http);
        if (parse_json && !response.http.body.empty())
        {
            ii::json::Limits limits; limits.input_bytes = limit;
            auto parsed = ii::json::parse(response.http.body, limits);
            if (parsed) response.json = std::move(*parsed);
            else if (!response.error) response.error = application_error(ErrorCode::malformed, parsed.error().message);
        }
        callback(std::move(response));
    });
}
void RestClient::cancel() { transport_.cancel(); }
bool GraphQLResponse::ok() const
{ return !error && errors.empty() && data.has_value() && http.status >= 200 && http.status < 300; }
GraphQLClient::GraphQLClient(HttpTransport& transport, std::string endpoint) : transport_(transport), endpoint_(std::move(endpoint)) {}
Result<HttpRequest> GraphQLClient::prepare(const GraphQLRequest& operation) const
{
    if (wire::trim(operation.query).empty()) return fail(Layer::application, ErrorCode::invalid_argument, "GraphQL query is empty");
    HttpRequest request; request.method = "POST"; request.url = endpoint_;
    if (!options(request, operation.options)) return fail(Layer::application, ErrorCode::invalid_argument, "Invalid GraphQL request options");
    core::Value::Object envelope{{"query", core::Value(operation.query)}, {"variables", core::Value(operation.variables)}};
    if (!operation.operation_name.empty()) envelope.emplace("operationName", core::Value(operation.operation_name));
    if (!operation.extensions.empty()) envelope.emplace("extensions", core::Value(operation.extensions));
    auto body = ii::json::stringify(core::Value(std::move(envelope)));
    if (!body) return fail(Layer::application, ErrorCode::malformed, body.error().message);
    request.body = std::move(*body);
    set_header(request, "Content-Type", "application/json");
    set_header(request, "Accept", "application/graphql-response+json, application/json;q=0.9");
    if (!detail::http_request(request)) return fail(Layer::application, ErrorCode::invalid_argument, "Invalid GraphQL HTTP request");
    return request;
}
bool GraphQLClient::execute(GraphQLRequest operation, std::function<void(GraphQLResponse)> callback)
{
    if (!callback) return false;
    auto request = prepare(operation); if (!request) return false;
    auto limit = request->maximum_bytes;
    return transport_.start(std::move(*request), [callback = std::move(callback), limit](HttpResponse response)
    { callback(decode(std::move(response), limit)); });
}
void GraphQLClient::cancel() { transport_.cancel(); }
GraphQLResponse GraphQLClient::decode(HttpResponse http, std::size_t limit)
{
    GraphQLResponse response; response.http = std::move(http); response.error = response_error(response.http);
    auto invalid = [&](std::string message)
    {
        response.error = application_error(ErrorCode::malformed, std::move(message));
        response.data.reset(); response.errors.clear(); response.extensions.clear();
    };
    if (response.http.body.size() > limit)
    { response.error = application_error(ErrorCode::too_large, "GraphQL response limit exceeded"); return response; }
    ii::json::Limits limits; limits.input_bytes = limit;
    auto tree = ii::json::parse(response.http.body, limits);
    if (!tree || !tree->get<core::Value::Object>())
    { invalid("GraphQL response must be a JSON object"); return response; }
    const auto& object = tree->get<core::Value::Object>()->get();
    auto data = object.find("data"), errors = object.find("errors"), extensions = object.find("extensions");
    if (data != object.end())
    {
        if (!data->second.get<core::Value::Object>() && data->second != core::Value{})
        { invalid("GraphQL data must be an object or null"); return response; }
        response.data = data->second;
    }
    if (extensions != object.end())
    {
        auto extra = extensions->second.get<core::Value::Object>();
        if (!extra) { invalid("GraphQL extensions must be an object"); return response; }
        response.extensions = extra->get();
    }
    if (errors != object.end())
    {
        auto list = errors->second.get<core::Value::Array>();
        if (!list || list->get().empty()) { invalid("GraphQL errors must be a nonempty array"); return response; }
        for (const auto& item : list->get())
        {
            auto error = item.get<core::Value::Object>();
            if (!error) { invalid("GraphQL error must be an object"); return response; }
            const auto& fields = error->get();
            auto message = fields.find("message");
            if (message == fields.end() || !message->second.get<std::string>())
            { invalid("GraphQL error requires a string message"); return response; }
            GraphQLError decoded; decoded.message = message->second.get<std::string>()->get();
            for (const auto& [key, value] : fields)
            {
                if (key == "extensions")
                {
                    auto map = value.get<core::Value::Object>();
                    if (!map) { invalid("GraphQL error extensions must be an object"); return response; }
                    decoded.extensions = map->get();
                }
                else if (key == "locations" || key == "path")
                {
                    auto array = value.get<core::Value::Array>();
                    if (!array) { invalid("GraphQL error locations/path must be arrays"); return response; }
                    for (const auto& entry : array->get())
                    {
                        if (key == "path" && !entry.get<std::string>() && !integer(entry, false))
                        { invalid("Invalid GraphQL error path"); return response; }
                        if (key == "locations" && (!entry.get<core::Value::Object>() ||
                            !integer(wire::field(entry, "line"), true) || !integer(wire::field(entry, "column"), true)))
                        { invalid("Invalid GraphQL error location"); return response; }
                    }
                    (key == "path" ? decoded.path : decoded.locations) = array->get();
                }
            }
            response.errors.push_back(std::move(decoded));
        }
    }
    if (!response.data && response.errors.empty()) invalid("GraphQL response requires data or errors");
    return response;
}
Result<void> HttpRouter::add(std::string method, std::string pattern, Handler handler)
{
    if (!detail::token(method) || !handler || !pattern.starts_with('/') || pattern.find_first_of("?#%\\") != pattern.npos ||
        pattern.size() > 16384 || entries_.size() >= 4096)
        return fail(Layer::application, ErrorCode::invalid_argument, "Invalid route method, handler or pattern");
    auto parts = segments(pattern); std::set<std::string> names;
    for (const auto& part : parts)
    {
        if (parameter(part))
        {
            auto name = part.substr(1, part.size() - 2);
            if (!detail::token(name) || !names.insert(name).second)
                return fail(Layer::application, ErrorCode::invalid_argument, "Invalid or duplicate route parameter");
        }
        else if (part.find_first_of("{}") != part.npos)
            return fail(Layer::application, ErrorCode::invalid_argument, "Route parameter must occupy an entire segment");
    }
    for (const auto& entry : entries_)
    {
        if (entry.method != method || entry.segments.size() != parts.size()) continue;
        bool same = true;
        for (std::size_t i = 0; i < parts.size(); ++i)
            if (!(entry.segments[i] == parts[i] || (parameter(entry.segments[i]) && parameter(parts[i])))) { same = false; break; }
        if (same) return fail(Layer::application, ErrorCode::invalid_argument, "Duplicate route shape");
    }
    entries_.push_back({std::move(method), std::move(pattern), std::move(parts), std::move(handler)}); return {};
}
ServerResponse HttpRouter::dispatch(const ServerRequest& request) const
{
    if (!detail::token(request.method) || !request.target.starts_with('/') || request.target.starts_with("//") ||
        request.target.size() > 65536 || request.target.find('#') != request.target.npos)
        return {400, {}, "Invalid request target"};
    auto parts = segments(std::string_view(request.target).substr(0, request.target.find('?')));
    for (auto& part : parts)
    {
        auto decoded = wire::percent_decode(part);
        if (!decoded || decoded->find_first_of(std::string("\0/\\", 3)) != decoded->npos ||
            *decoded == "." || *decoded == ".." || !detail::header_value(*decoded))
            return {400, {}, "Invalid encoded path segment"};
        part = std::move(*decoded);
    }
    const Entry* best = nullptr; std::size_t best_specificity = 0; Parameters parameters;
    std::set<std::string> allowed;
    for (const auto& entry : entries_)
    {
        if (entry.segments.size() != parts.size()) continue;
        bool matches = true; std::size_t specificity = 0; Parameters candidate;
        for (std::size_t i = 0; i < parts.size(); ++i)
        {
            if (parameter(entry.segments[i]))
            {
                if (parts[i].empty()) { matches = false; break; }
                candidate.emplace(entry.segments[i].substr(1, entry.segments[i].size() - 2), parts[i]);
            }
            else if (entry.segments[i] != parts[i]) { matches = false; break; }
            else ++specificity;
        }
        if (!matches) continue;
        allowed.insert(entry.method);
        if (entry.method == request.method && (!best || specificity > best_specificity))
        { best = &entry; best_specificity = specificity; parameters = std::move(candidate); }
    }
    if (!best)
    {
        if (allowed.empty()) return {404, {}, "Route not found"};
        std::string allow;
        for (const auto& method : allowed) { if (!allow.empty()) allow += ", "; allow += method; }
        return {405, {{"Allow", std::move(allow)}}, "Method not allowed"};
    }
    // Copy the callable so registration from inside a handler cannot invalidate it.
    auto handler = best->handler;
    try { return handler(request, parameters); }
    catch (...) { return {500, {}, "Route handler failed"}; }
}
std::unique_ptr<NativeHttpTransport> ApplicationLayer::http() const { return std::make_unique<NativeHttpTransport>(loop_); }
RestClient ApplicationLayer::rest(HttpTransport& transport, std::string base) const { return RestClient(transport, std::move(base)); }
GraphQLClient ApplicationLayer::graphql(HttpTransport& transport, std::string endpoint) const { return GraphQLClient(transport, std::move(endpoint)); }
} // namespace ii::network
