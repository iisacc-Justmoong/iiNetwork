#include <iiNetwork/Http.h>
#include "HttpInternal.h"
#include <curl/curl.h>
#include <algorithm>
#include <limits>
#include <mutex>
#include <charconv>
#include <set>
#include <utility>

namespace ii::network
{
using namespace std::chrono_literals;
std::string_view method_name(HttpMethod value)
{
    switch (value)
    {
        case HttpMethod::get: return "GET"; case HttpMethod::head: return "HEAD";
        case HttpMethod::post: return "POST"; case HttpMethod::put: return "PUT";
        case HttpMethod::patch: return "PATCH"; case HttpMethod::delete_: return "DELETE";
        case HttpMethod::options: return "OPTIONS"; case HttpMethod::trace: return "TRACE";
        case HttpMethod::connect: return "CONNECT";
    }
    return {};
}
namespace
{
void initialize_curl()
{ static std::once_flag flag; std::call_once(flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); }); }
bool c_string(std::string_view value) { return value.find('\0') == value.npos; }
std::string lower(std::string value) { for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 32; return value; }
long curl_http_version(HttpVersion value)
{
    switch (value)
    {
        case HttpVersion::automatic: return CURL_HTTP_VERSION_NONE;
        case HttpVersion::http1_0: return CURL_HTTP_VERSION_1_0;
        case HttpVersion::http1_1: return CURL_HTTP_VERSION_1_1;
        case HttpVersion::http2: return CURL_HTTP_VERSION_2TLS;
        case HttpVersion::http2_prior_knowledge: return CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
#if LIBCURL_VERSION_NUM >= 0x074200
        case HttpVersion::http3: return CURL_HTTP_VERSION_3;
#endif
        default: return -1;
    }
}
HttpVersion http_version(long value)
{
    if (value == CURL_HTTP_VERSION_1_0) return HttpVersion::http1_0;
    if (value == CURL_HTTP_VERSION_1_1) return HttpVersion::http1_1;
    if (value == CURL_HTTP_VERSION_2_0) return HttpVersion::http2;
#if LIBCURL_VERSION_NUM >= 0x074200
    if (value == CURL_HTTP_VERSION_3) return HttpVersion::http3;
#endif
    return HttpVersion::automatic;
}
}
namespace detail
{
bool http_url(std::string_view url)
{
    if (url.empty() || url.size() > 65536) return false;
    for (unsigned char c : url) if (c <= 32 || c == 127 || c == '\\') return false;
    auto parsed = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>(curl_url(), curl_url_cleanup);
    if (!parsed || curl_url_set(parsed.get(), CURLUPART_URL, std::string(url).c_str(), 0) != CURLUE_OK) return false;
    auto part = [&](CURLUPart key) -> std::optional<std::string>
    {
        char* raw = nullptr;
        if (curl_url_get(parsed.get(), key, &raw, 0) != CURLUE_OK) return {};
        std::string value(raw); curl_free(raw); return value;
    };
    auto scheme = part(CURLUPART_SCHEME), host = part(CURLUPART_HOST);
    return scheme && (*scheme == "http" || *scheme == "https") && host && !host->empty() &&
           !part(CURLUPART_USER) && !part(CURLUPART_PASSWORD) && !part(CURLUPART_FRAGMENT);
}
bool http_request(const HttpRequest& request)
{
    if (!http_url(request.url) || !token(request.method) || request.headers.size() > 128 ||
        request.timeout.count() <= 0 || request.timeout.count() > std::numeric_limits<long>::max() ||
        request.initial_response_timeout.count() < 0 || request.inactivity_timeout.count() < 0 ||
        request.timeout > std::chrono::hours(24 * 365) || request.initial_response_timeout > std::chrono::hours(24 * 365) ||
        request.inactivity_timeout > std::chrono::hours(24 * 365) || request.connect_timeout > std::chrono::hours(24 * 365) ||
        request.connect_timeout.count() < 0 || request.connect_timeout.count() > std::numeric_limits<long>::max() ||
        request.maximum_redirects > 32 || request.headers.size() + request.header_fields.size() > 128 || !validate(request.tls) ||
        (request.follow_redirects && request.tls.public_key_sha256) ||
        (request.upload && !request.body.empty()) || (!request.upload && request.upload_size) ||
        (request.upload_size && *request.upload_size > static_cast<std::uint64_t>(std::numeric_limits<curl_off_t>::max())) ||
        (request.method == "HEAD" && (request.upload || !request.body.empty())) ||
        !c_string(request.user_agent) || !header_value(request.user_agent) || !c_string(request.unix_socket_path) ||
        request.unix_socket_path.size() > 32768 || !header_value(request.cookie) || request.cookie.size() > 16384 ||
        !c_string(request.authentication.username) || !c_string(request.authentication.password) ||
        !header_value(request.authentication.token) || !c_string(request.proxy.username) || !c_string(request.proxy.password) ||
        !header_value(request.proxy.address)) return false;
    if (request.proxy.type < ProxyType::system || request.proxy.type > ProxyType::socks5_hostname ||
        request.authentication.scheme < HttpAuthScheme::none || request.authentication.scheme > HttpAuthScheme::bearer ||
        (request.proxy.type != ProxyType::system && request.proxy.type != ProxyType::disabled && request.proxy.address.empty())) return false;
    if (request.authentication.scheme == HttpAuthScheme::bearer &&
        (request.authentication.token.empty() || request.authentication.token.find_first_of(" \t") != std::string::npos)) return false;
    std::size_t header_bytes = 0;
    std::set<std::string> singleton;
    auto field = [&](const std::string& key, const std::string& value)
    {
        if (!token(key) || !header_value(value) || key.size() > 8192 || value.size() > 65536) return false;
        auto name = lower(key);
        if (name == "transfer-encoding") return false;
        if ((name == "host" || name == "content-length" || name == "authorization") && !singleton.insert(name).second) return false;
        if (name == "authorization" && request.authentication.scheme != HttpAuthScheme::none) return false;
        if (name == "content-length")
        {
            std::uint64_t count = 0; auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), count);
            if (value.empty() || error != std::errc{} || end != value.data() + value.size() ||
                (request.upload ? !request.upload_size || count != *request.upload_size : count != request.body.size())) return false;
        }
        header_bytes += key.size() + value.size();
        return header_bytes <= 65536;
    };
    for (const auto& [key, value] : request.headers) if (!field(key, value)) return false;
    for (const auto& [key, value] : request.header_fields.entries()) if (!field(key, value)) return false;
    return true;
}
} // namespace detail
struct Http::Impl
{
    runtime::EventLoop& loop;
    CURLM* multi = nullptr;
    CURLSH* share = nullptr;
    CURL* easy = nullptr;
    curl_slist* headers = nullptr;
    runtime::TaskToken tick;
    HttpResponse response;
    HttpRequest request;
    std::size_t received = 0, header_received = 0;
    runtime::Clock::time_point started{}, last_received{};
    std::uint64_t progress_total = 0, progress_received = 0, last_progress = UINT64_MAX;
    std::function<void(HttpResponse)> completion;
    std::optional<Error> last_error;
    TransferProgress progress;
    bool headers_complete = false;
    bool alive = true, performing = false, stop_requested = false;
    explicit Impl(runtime::EventLoop& l) : loop(l)
    {
        initialize_curl();
        multi = curl_multi_init();
        share = curl_share_init();
        if (share) { curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE); curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS); }
    }
    void clear()
    {
        tick.cancel();
        if (easy)
        {
            curl_multi_remove_handle(multi, easy);
            curl_easy_cleanup(easy);
            easy = nullptr;
        }
        curl_slist_free_all(headers);
        headers = nullptr;
        std::fill(request.body.begin(), request.body.end(), '\0');
        request.body.clear();
        request.headers.clear();
        request.consume = {};
        request.progress = {};
        request.upload = {}; request.transfer_progress = {}; request.received_headers = {};
        auto cleanse = [](std::string& secret) { std::fill(secret.begin(), secret.end(), '\0'); secret.clear(); };
        cleanse(request.authentication.password); cleanse(request.authentication.token);
        cleanse(request.proxy.password); cleanse(request.tls.identity.private_key_password);
        stop_requested = false;
    }
    ~Impl()
    {
        clear();
        curl_multi_cleanup(multi);
        if (share) curl_share_cleanup(share);
    }
    void metadata(CURLcode code)
    {
        response.native_error = code;
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response.status);
        auto text = [&](CURLINFO key, std::string& output) { char* value = nullptr; if (curl_easy_getinfo(easy, key, &value) == CURLE_OK && value) output = value; };
        text(CURLINFO_EFFECTIVE_URL, response.effective_url); text(CURLINFO_CONTENT_TYPE, response.content_type);
        text(CURLINFO_PRIMARY_IP, response.primary_ip); text(CURLINFO_LOCAL_IP, response.local_ip);
        curl_easy_getinfo(easy, CURLINFO_PRIMARY_PORT, &response.primary_port); curl_easy_getinfo(easy, CURLINFO_LOCAL_PORT, &response.local_port);
        curl_easy_getinfo(easy, CURLINFO_REDIRECT_COUNT, &response.redirect_count);
        long version = 0; curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &version); response.version = http_version(version);
        auto timing = [&](CURLINFO key) { curl_off_t value = 0; curl_easy_getinfo(easy, key, &value); return std::chrono::microseconds(value); };
        response.timings = {timing(CURLINFO_NAMELOOKUP_TIME_T), timing(CURLINFO_CONNECT_TIME_T), timing(CURLINFO_APPCONNECT_TIME_T), timing(CURLINFO_STARTTRANSFER_TIME_T), timing(CURLINFO_TOTAL_TIME_T)};
        curl_off_t downloaded = 0, uploaded = 0; curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &downloaded); curl_easy_getinfo(easy, CURLINFO_SIZE_UPLOAD_T, &uploaded);
        response.transfer = progress; response.transfer.downloaded = static_cast<std::uint64_t>(std::max<curl_off_t>(0, downloaded));
        response.transfer.uploaded = static_cast<std::uint64_t>(std::max<curl_off_t>(0, uploaded));
    }
};
Http::Http(runtime::EventLoop& l) : p_(std::make_shared<Impl>(l))
{
}
Http::~Http()
{
    p_->alive = false;
    cancel();
}
bool Http::start(HttpRequest request, std::function<void(HttpResponse)> completion)
{
    p_->last_error.reset();
    if (busy() || !completion || !detail::http_request(request))
    { p_->last_error = Error{ErrorCode::invalid_argument, Layer::application, "HTTP request is busy, invalid or lacks a completion"}; return false; }
    auto capabilities = Http::capabilities();
    if (curl_http_version(request.version) < 0 ||
        ((request.version == HttpVersion::http2 || request.version == HttpVersion::http2_prior_knowledge) && !capabilities.http2) ||
        (request.version == HttpVersion::http3 && !capabilities.http3) || (!request.unix_socket_path.empty() && !capabilities.unix_sockets))
    { p_->last_error = Error{ErrorCode::unsupported, Layer::application, "Requested HTTP version or local socket is not supported by this libcurl backend"}; return false; }
    auto& p = *p_;
    p.request = std::move(request);
    p.response = {};
    p.progress = {}; p.headers_complete = false;
    p.received = p.header_received = 0;
    p.progress_total = p.progress_received = 0;
    p.last_progress = UINT64_MAX;
    p.started = p.last_received = runtime::Clock::now();
    p.completion = std::move(completion);
    p.easy = p.multi && p.share ? curl_easy_init() : nullptr;
    if (!p.easy)
    {
        p.completion = {};
        return false;
    }
    CURLcode configuration = CURLE_OK;
    auto option = [&](CURLoption name, auto value) { if (configuration == CURLE_OK) configuration = curl_easy_setopt(p.easy, name, value); };
    if (p.request.enable_cookies) option(CURLOPT_SHARE, p.share);
    option(CURLOPT_HTTP_VERSION, curl_http_version(p.request.version));
    option(CURLOPT_SSL_VERIFYPEER, 1L); option(CURLOPT_SSL_VERIFYHOST, 2L);
    long tls_min = p.request.tls.minimum == TlsVersion::tls1_2 ? CURL_SSLVERSION_TLSv1_2 : CURL_SSLVERSION_TLSv1_3;
    long tls_max = p.request.tls.maximum == TlsVersion::tls1_2 ? CURL_SSLVERSION_MAX_TLSv1_2 : CURL_SSLVERSION_MAX_TLSv1_3;
    option(CURLOPT_SSLVERSION, tls_min | tls_max);
    if (!p.request.tls.ca_file.empty()) option(CURLOPT_CAINFO, p.request.tls.ca_file.c_str());
    if (!p.request.tls.ca_directory.empty()) option(CURLOPT_CAPATH, p.request.tls.ca_directory.c_str());
    auto& identity = p.request.tls.identity;
    if (!identity.certificate_chain_file.empty()) { option(CURLOPT_SSLCERT, identity.certificate_chain_file.c_str()); option(CURLOPT_SSLKEY, identity.private_key_file.c_str()); }
    if (!identity.private_key_password.empty()) option(CURLOPT_KEYPASSWD, identity.private_key_password.c_str());
    if (p.request.tls.public_key_sha256) { auto pin = public_key_pin(*p.request.tls.public_key_sha256); option(CURLOPT_PINNEDPUBLICKEY, pin.c_str()); }
    switch (p.request.authentication.scheme)
    {
        case HttpAuthScheme::none: break;
        case HttpAuthScheme::basic: option(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_BASIC)); break;
        case HttpAuthScheme::digest: option(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_DIGEST)); break;
        case HttpAuthScheme::bearer: option(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_BEARER)); option(CURLOPT_XOAUTH2_BEARER, p.request.authentication.token.c_str()); break;
        default: configuration = CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (!p.request.authentication.username.empty()) option(CURLOPT_USERNAME, p.request.authentication.username.c_str());
    if (!p.request.authentication.password.empty()) option(CURLOPT_PASSWORD, p.request.authentication.password.c_str());
    option(CURLOPT_UNRESTRICTED_AUTH, 0L);
    if (p.request.proxy.type == ProxyType::disabled || !p.request.unix_socket_path.empty()) option(CURLOPT_PROXY, "");
    else if (p.request.proxy.type != ProxyType::system)
    {
        option(CURLOPT_PROXY, p.request.proxy.address.c_str());
        option(CURLOPT_NOPROXY, "");
        long type = p.request.proxy.type == ProxyType::http ? CURLPROXY_HTTP : p.request.proxy.type == ProxyType::socks5 ? CURLPROXY_SOCKS5 : CURLPROXY_SOCKS5_HOSTNAME;
        option(CURLOPT_PROXYTYPE, type);
        option(CURLOPT_PROXYUSERNAME, p.request.proxy.username.c_str()); option(CURLOPT_PROXYPASSWORD, p.request.proxy.password.c_str());
    }
    if (!p.request.unix_socket_path.empty()) option(CURLOPT_UNIX_SOCKET_PATH, p.request.unix_socket_path.c_str());
    if (!p.request.user_agent.empty()) option(CURLOPT_USERAGENT, p.request.user_agent.c_str());
    if (p.request.accept_compression) option(CURLOPT_ACCEPT_ENCODING, "");
    if (p.request.enable_cookies) option(CURLOPT_COOKIEFILE, "");
    if (!p.request.cookie.empty()) option(CURLOPT_COOKIE, p.request.cookie.c_str());
    curl_easy_setopt(p.easy, CURLOPT_URL, p.request.url.c_str());
    curl_easy_setopt(p.easy, CURLOPT_CUSTOMREQUEST, p.request.method.c_str());
    curl_easy_setopt(p.easy, CURLOPT_NOBODY, p.request.method == "HEAD" ? 1L : 0L);
    curl_easy_setopt(p.easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(p.easy, CURLOPT_TIMEOUT_MS, static_cast<long>(p.request.timeout.count()));
    curl_easy_setopt(p.easy, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(p.request.connect_timeout.count() ? p.request.connect_timeout.count() : p.request.timeout.count()));
    curl_easy_setopt(p.easy, CURLOPT_FOLLOWLOCATION, p.request.follow_redirects ? 1L : 0L);
    curl_easy_setopt(p.easy, CURLOPT_MAXREDIRS, static_cast<long>(p.request.maximum_redirects));
    curl_easy_setopt(p.easy, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(p.easy, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    // HTTP is accepted for explicit local test endpoints; callers own production HTTPS policy.
    if (!p.request.upload && (!p.request.body.empty() || p.request.method == "POST"))
    {
        curl_easy_setopt(p.easy, CURLOPT_POSTFIELDS, p.request.body.data());
        curl_easy_setopt(p.easy, CURLOPT_POSTFIELDSIZE_LARGE,
                         static_cast<curl_off_t>(p.request.body.size()));
    }
    for (const auto& [key, value] : p.request.headers)
        p.headers = curl_slist_append(p.headers, (key + ": " + value).c_str());
    for (const auto& [key, value] : p.request.header_fields.entries())
        p.headers = curl_slist_append(p.headers, (key + ": " + value).c_str());
    if (p.request.upload)
    {
        if (p.request.method == "POST") { option(CURLOPT_POST, 1L); option(CURLOPT_POSTFIELDSIZE_LARGE, p.request.upload_size ? static_cast<curl_off_t>(*p.request.upload_size) : curl_off_t(-1)); }
        else { option(CURLOPT_UPLOAD, 1L); option(CURLOPT_INFILESIZE_LARGE, p.request.upload_size ? static_cast<curl_off_t>(*p.request.upload_size) : curl_off_t(-1)); }
        option(CURLOPT_READDATA, &p);
        option(CURLOPT_READFUNCTION, +[](char* output, std::size_t size, std::size_t count, void* raw) -> std::size_t
        {
            auto& p = *static_cast<Impl*>(raw);
            if (p.stop_requested || !p.alive || (size && count > std::numeric_limits<std::size_t>::max() / size)) return CURL_READFUNC_ABORT;
            try { auto callback = p.request.upload; auto written = callback(output, size * count); return p.stop_requested || !p.alive || written > size * count ? CURL_READFUNC_ABORT : written; }
            catch (...) { return CURL_READFUNC_ABORT; }
        });
    }
    curl_easy_setopt(p.easy, CURLOPT_HTTPHEADER, p.headers);
    curl_easy_setopt(p.easy, CURLOPT_WRITEDATA, &p);
    curl_easy_setopt(
        p.easy, CURLOPT_WRITEFUNCTION,
        +[](char* data, std::size_t size, std::size_t count, void* raw) -> std::size_t
        {
            auto& p = *static_cast<Impl*>(raw);
            if (size && count > std::numeric_limits<std::size_t>::max() / size)
                return 0;
            const auto n = size * count;
            if (n > p.request.maximum_bytes - p.received)
            {
                p.response.too_large = true;
                return 0;
            }
            p.received += n;
            if (n)
                p.last_received = runtime::Clock::now();
            if (p.stop_requested || !p.alive) return 0;
            if (p.request.consume)
            {
                try
                {
                    auto consume = p.request.consume;
                    if (!consume(std::string_view(data, n)) || p.stop_requested || !p.alive)
                        return 0;
                }
                catch (...)
                {
                    return 0;
                }
            }
            else
                p.response.body.append(data, n);
            return n;
        });
    curl_easy_setopt(p.easy, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(p.easy, CURLOPT_XFERINFODATA, &p);
    curl_easy_setopt(
        p.easy, CURLOPT_XFERINFOFUNCTION,
        +[](void* raw, curl_off_t total, curl_off_t received, curl_off_t upload_total, curl_off_t uploaded) -> int
        {
            auto& p = *static_cast<Impl*>(raw);
            p.progress_received = static_cast<std::uint64_t>(std::max<curl_off_t>(received, 0));
            p.progress_total = static_cast<std::uint64_t>(std::max<curl_off_t>(total, 0));
            p.progress.download_total = p.progress_total; p.progress.downloaded = p.progress_received;
            p.progress.upload_total = static_cast<std::uint64_t>(std::max<curl_off_t>(upload_total, 0));
            p.progress.uploaded = static_cast<std::uint64_t>(std::max<curl_off_t>(uploaded, 0));
            return 0;
        });
    curl_easy_setopt(p.easy, CURLOPT_HEADERDATA, &p);
    curl_easy_setopt(
        p.easy, CURLOPT_HEADERFUNCTION,
        +[](char* data, std::size_t size, std::size_t count, void* raw) -> std::size_t
        {
            if (size && count > std::numeric_limits<std::size_t>::max() / size)
                return 0;
            auto n = size * count;
            auto& p = *static_cast<Impl*>(raw);
            if (n > 64 * 1024 - p.header_received)
            { p.response.too_large = true; return 0; }
            p.header_received += n;
            std::string line(data, n);
            if (line.starts_with("HTTP/"))
            {
                p.response.headers.clear(); p.response.header_fields.clear(); p.response.trailers.clear(); p.headers_complete = false;
                auto space = line.find(' ');
                if (space != line.npos) std::from_chars(line.data() + space + 1, line.data() + line.size(), p.response.status);
            }
            if ((line == "\r\n" || line == "\n") && !p.headers_complete)
            {
                p.headers_complete = true;
                try { auto callback = p.request.received_headers; if (callback && (!callback(p.response.status, p.response.header_fields) || p.stop_requested || !p.alive)) return 0; }
                catch (...) { return 0; }
            }
            auto colon = line.find(':');
            if (colon != std::string::npos)
            {
                auto key = line.substr(0, colon);
                for (auto& c : key)
                    if (c >= 'A' && c <= 'Z')
                        c += 32;
                auto value = line.substr(colon + 1);
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                    value.erase(0, 1);
                while (!value.empty() &&
                       (value.back() == '\r' || value.back() == '\n' || value.back() == ' '))
                    value.pop_back();
                if (p.response.headers.size() >= 128 && !p.response.headers.contains(key))
                    return 0;
                auto& fields = p.headers_complete ? p.response.trailers : p.response.header_fields;
                if (!fields.append(key, value)) { p.response.too_large = true; return 0; }
                p.response.headers.insert_or_assign(std::move(key), std::move(value));
            }
            return n;
        });
    if (configuration != CURLE_OK || curl_multi_add_handle(p.multi, p.easy) != CURLM_OK)
    {
        p.last_error = Error{ErrorCode::unsupported, Layer::application, configuration == CURLE_OK ? "HTTP multi-handle admission failed" : curl_easy_strerror(configuration)};
        p.clear();
        p.completion = {};
        return false;
    }
    p.tick =
        p.loop
            .every(5ms,
                   [weak = std::weak_ptr<Impl>(p_)]
                   {
                       auto keep = weak.lock();
                       if (!keep || !keep->alive) return;
                       auto& p = *keep;
                       const auto now = runtime::Clock::now();
                       const bool initial = p.request.initial_response_timeout.count() > 0 &&
                                            p.received == 0 &&
                                            now - p.started >= p.request.initial_response_timeout;
                       const bool idle = p.request.inactivity_timeout.count() > 0 &&
                                         p.received > 0 &&
                                         now - p.last_received >= p.request.inactivity_timeout;
                       if (initial || idle)
                       {
                           p.response.timed_out = true;
                           p.response.error = "HTTP response deadline elapsed";
                           p.metadata(CURLE_OPERATION_TIMEDOUT);
                           auto response = std::move(p.response);
                           auto callback = std::move(p.completion);
                           p.clear();
                           if (callback)
                               callback(std::move(response));
                           return;
                       }
                       int running = 0;
                       p.performing = true;
                       auto code = curl_multi_perform(p.multi, &running);
                       p.performing = false;
                       if (p.stop_requested || !p.alive)
                       { p.clear(); return; }
                       int count = 0;
                       auto* message = curl_multi_info_read(p.multi, &count);
                       if (code == CURLM_OK && !message)
                       {
                           auto progress = p.request.progress;
                           auto transfer_progress = p.request.transfer_progress; auto transfer = p.progress;
                           auto got = p.progress_received, total = p.progress_total;
                           bool emit = got != p.last_progress;
                           p.last_progress = got;
                           if (emit && progress)
                               progress(got, total);
                           if (p.alive && p.easy && !p.stop_requested && transfer_progress) transfer_progress(transfer);
                           return;
                       }
                       CURLcode result = message ? message->data.result : CURLE_FAILED_INIT;
                       p.metadata(result);
                       p.response.timed_out = result == CURLE_OPERATION_TIMEDOUT;
                       if (result != CURLE_OK)
                           p.response.error = curl_easy_strerror(result);
                       auto response = std::move(p.response);
                       auto callback = std::move(p.completion);
                       p.clear();
                       if (callback)
                           callback(std::move(response));
                   })
            .token;
    if (!p.tick.pending())
    {
        p.completion = {};
        p.clear();
        return false;
    }
    return true;
}
void Http::cancel()
{
    p_->completion = {};
    if (p_->performing)
    {
        p_->stop_requested = true;
        p_->tick.cancel();
        return;
    }
    p_->clear();
}
bool Http::busy() const
{
    return p_->easy != nullptr;
}
Result<void> Http::request(HttpRequest request, std::function<void(HttpResponse)> complete)
{
    if (start(std::move(request), std::move(complete))) return {};
    return std::unexpected(p_->last_error.value_or(Error{ErrorCode::unavailable, Layer::application, "HTTP request admission failed"}));
}
std::optional<Error> Http::last_error() const { return p_->last_error; }
HttpCapabilities Http::capabilities()
{
    initialize_curl(); auto* info = curl_version_info(CURLVERSION_NOW); HttpCapabilities result;
    if (!info) return result;
    result.libcurl_version = info->version; if (info->ssl_version) result.tls_backend = info->ssl_version;
    result.tls = (info->features & CURL_VERSION_SSL) != 0; result.ipv6 = (info->features & CURL_VERSION_IPV6) != 0;
    result.http2 = (info->features & CURL_VERSION_HTTP2) != 0; result.unix_sockets = (info->features & CURL_VERSION_UNIX_SOCKETS) != 0;
#if LIBCURL_VERSION_NUM >= 0x074200
    result.http3 = (info->features & CURL_VERSION_HTTP3) != 0;
#endif
    return result;
}
Result<std::vector<std::string>> Http::cookies() const
{
    if (!p_->share || p_->performing) return detail::fail(Layer::application, ErrorCode::invalid_state, "Cookie access is unavailable inside a transfer callback");
    auto easy = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(), curl_easy_cleanup);
    if (!easy) return detail::fail(Layer::application, ErrorCode::unavailable, "Cookie handle allocation failed");
    curl_easy_setopt(easy.get(), CURLOPT_SHARE, p_->share); curl_easy_setopt(easy.get(), CURLOPT_COOKIEFILE, "");
    curl_slist* raw = nullptr; auto code = curl_easy_getinfo(easy.get(), CURLINFO_COOKIELIST, &raw);
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> guard(raw, curl_slist_free_all);
    if (code != CURLE_OK) return detail::fail(Layer::application, ErrorCode::io_error, curl_easy_strerror(code));
    std::vector<std::string> result;
    for (auto* item = raw; item; item = item->next)
    {
        if (result.size() >= 4096) return detail::fail(Layer::application, ErrorCode::too_large, "Cookie export exceeds 4096 entries");
        result.emplace_back(item->data);
    }
    return result;
}
Result<void> Http::set_cookie(std::string_view value)
{
    if (!p_->share || p_->performing || value.size() > 16384 || !detail::header_value(value))
        return detail::fail(Layer::application, ErrorCode::invalid_argument, "Invalid cookie line or transfer callback context");
    if (value != "ALL")
    {
        std::vector<std::string_view> fields; auto rest = value;
        for (;;) { auto tab = rest.find('\t'); fields.push_back(rest.substr(0, tab)); if (tab == rest.npos) break; rest.remove_prefix(tab + 1); }
        if (fields.size() != 7 || fields[0].empty() || (fields[1] != "TRUE" && fields[1] != "FALSE") ||
            !fields[2].starts_with('/') || (fields[3] != "TRUE" && fields[3] != "FALSE") || fields[4].empty() || !detail::token(fields[5]))
            return detail::fail(Layer::application, ErrorCode::invalid_argument, "Expected a seven-field Netscape cookie line");
        std::uint64_t expiry = 0; auto [end, error] = std::from_chars(fields[4].data(), fields[4].data() + fields[4].size(), expiry);
        if (error != std::errc{} || end != fields[4].data() + fields[4].size()) return detail::fail(Layer::application, ErrorCode::invalid_argument, "Invalid cookie expiry");
    }
    auto easy = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(), curl_easy_cleanup);
    if (!easy) return detail::fail(Layer::application, ErrorCode::unavailable, "Cookie handle allocation failed");
    curl_easy_setopt(easy.get(), CURLOPT_SHARE, p_->share); curl_easy_setopt(easy.get(), CURLOPT_COOKIEFILE, "");
    auto code = curl_easy_setopt(easy.get(), CURLOPT_COOKIELIST, std::string(value).c_str());
    if (code != CURLE_OK) return detail::fail(Layer::application, ErrorCode::io_error, curl_easy_strerror(code));
    return {};
}
Result<void> Http::clear_cookies() { return set_cookie("ALL"); }
} // namespace ii::network
