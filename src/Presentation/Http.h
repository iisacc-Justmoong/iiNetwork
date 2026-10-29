#pragma once
#include <iiSDKCore/Runtime/EventLoop.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <iiNetwork/Headers.h>
#include <iiNetwork/Security.h>

namespace ii::network
{
enum class HttpMethod { get, head, post, put, patch, delete_, options, trace, connect };
std::string_view method_name(HttpMethod);
enum class HttpVersion { automatic, http1_0, http1_1, http2, http2_prior_knowledge, http3 };
enum class HttpAuthScheme { none, basic, digest, bearer };
struct HttpAuthentication final
{
    HttpAuthScheme scheme = HttpAuthScheme::none;
    std::string username, password, token;
};
enum class ProxyType { system, disabled, http, socks5, socks5_hostname };
struct HttpProxy final
{
    ProxyType type = ProxyType::system;
    std::string address, username, password;
};
struct TransferProgress final
{
    std::uint64_t download_total = 0, downloaded = 0, upload_total = 0, uploaded = 0;
};
struct HttpTimings final
{
    std::chrono::microseconds dns{}, connect{}, tls{}, first_byte{}, total{};
};
struct HttpCapabilities final
{
    std::string libcurl_version, tls_backend;
    bool tls = false, ipv6 = false, http2 = false, http3 = false, unix_sockets = false;
};
struct HttpRequest final
{
    std::string url, method = "GET", body;
    std::map<std::string, std::string> headers;
    std::chrono::milliseconds timeout{10000};
    std::chrono::milliseconds initial_response_timeout{0}, inactivity_timeout{0};
    std::size_t maximum_bytes = 2 * 1024 * 1024;
    bool follow_redirects = false;
    std::function<bool(std::string_view)> consume;
    std::function<void(std::uint64_t, std::uint64_t)> progress;
    HeaderFields header_fields;
    HttpVersion version = HttpVersion::automatic;
    TlsPolicy tls;
    HttpAuthentication authentication;
    HttpProxy proxy;
    std::chrono::milliseconds connect_timeout{0}; // zero uses timeout
    unsigned maximum_redirects = 5;
    bool enable_cookies = false, accept_compression = false;
    std::string cookie, unix_socket_path, user_agent;
    std::function<std::size_t(char*, std::size_t)> upload;
    std::optional<std::uint64_t> upload_size;
    std::function<void(TransferProgress)> transfer_progress;
    std::function<bool(long, const HeaderFields&)> received_headers;
    void set_method(HttpMethod value) { method = method_name(value); }
};
struct HttpResponse final
{
    long status = 0;
    std::string body, error;
    std::map<std::string, std::string> headers;
    bool timed_out = false, too_large = false, cancelled = false;
    HeaderFields header_fields, trailers;
    std::string effective_url, content_type, primary_ip, local_ip;
    long primary_port = 0, local_port = 0, redirect_count = 0, native_error = 0;
    HttpVersion version = HttpVersion::automatic;
    TransferProgress transfer;
    HttpTimings timings;
    [[nodiscard]] bool ok() const { return error.empty() && status >= 200 && status < 300; }
};
class Http final
{
  public:
    explicit Http(runtime::EventLoop&);
    ~Http();
    bool start(HttpRequest, std::function<void(HttpResponse)>);
    Result<void> request(HttpRequest, std::function<void(HttpResponse)>);
    void cancel();
    [[nodiscard]] bool busy() const;
    [[nodiscard]] std::optional<Error> last_error() const;
    Result<std::vector<std::string>> cookies() const;
    Result<void> set_cookie(std::string_view netscape_cookie);
    Result<void> clear_cookies();
    [[nodiscard]] static HttpCapabilities capabilities();

  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
