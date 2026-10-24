#include <iiNetwork/Network.h>
#include <iiNetwork/Server.h>
#include <iiNetwork/Wire.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#ifndef _WIN32
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

using namespace ii::network;
using namespace std::chrono_literals;
namespace
{
std::filesystem::path fixtures;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template <class T, class E> T take(std::expected<T, E> value)
{ if (!value) throw std::runtime_error(value.error().message); return std::move(*value); }
void pass(Result<void> value) { if (!value) throw std::runtime_error(value.error().message); }
template <class Predicate> void until(ii::runtime::EventLoop& loop, Predicate done, std::chrono::milliseconds timeout = 5s)
{
    auto end = ii::runtime::Clock::now() + timeout;
    while (!done() && ii::runtime::Clock::now() < end) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(done(), "Core callback deadline elapsed");
}
IpEndpoint loopback(std::uint16_t port = 0, AddressFamily family = AddressFamily::ipv4) { return {IpAddress::loopback(family), port}; }
std::string file(std::string_view name) { return (fixtures / name).string(); }
std::string read_file(std::string path) { std::ifstream input(path, std::ios::binary); return {std::istreambuf_iterator<char>(input), {}}; }
bool local_entry_exists(const std::string& path)
{
#ifdef _WIN32
    // AF_UNIX endpoints are reparse entries; following them as ordinary files
    // makes std::filesystem::exists fail with ERROR_CANT_ACCESS_FILE.
    return GetFileAttributesW(std::filesystem::path(path).c_str()) != INVALID_FILE_ATTRIBUTES;
#else
    return std::filesystem::exists(path);
#endif
}
TlsOptions server_options(bool mutual = false)
{
    TlsOptions options; options.policy.identity = {file("server.pem"), file("server.key"), {}};
    options.policy.ca_file = file("ca.pem"); options.require_client_certificate = mutual;
    return options;
}
TlsOptions client_options(bool identity = false)
{
    TlsOptions options; options.policy.ca_file = file("ca.pem");
    if (identity) options.policy.identity = {file("client.pem"), file("client.key"), {}};
    return options;
}
HttpResponse exchange(Http& http, ii::runtime::EventLoop& loop, HttpRequest request)
{
    bool complete = false; HttpResponse response;
    pass(http.request(std::move(request), [&](HttpResponse value) { response = std::move(value); complete = true; }));
    until(loop, [&] { return complete; }); return response;
}
void addresses()
{
    auto system_trust = take(TlsContext::client());
    require(system_trust->role() == TlsRole::client, "default native trust context initialization");
    auto v4 = take(IpAddress::parse("127.0.0.1")), v6 = take(IpAddress::parse("::1"));
    require(v4.is_loopback() && v6.is_loopback() && ipv4(v4.string()) && ipv6(v6.string()), "IP family/loopback");
    require(take(IpEndpoint::parse("[::1]:443")).string() == "[::1]:443", "IPv6 endpoint formatting");
    require(!IpEndpoint::parse("::1:443") && !IpEndpoint::parse("127.0.0.1:65536") && !IpAddress::parse("1.2.3.4%1"), "invalid endpoint accepted");
    auto subnet = take(IpSubnet::parse("2001:db8::/32"));
    require(subnet.contains(take(IpAddress::parse("2001:db8::f"))) && !subnet.contains(v6), "IPv6 subnet");
    require(!IpSubnet::parse("::/129") && take(IpAddress::parse("ff02::1")).is_multicast() && take(IpAddress::parse("fe80::1")).is_link_local(), "IPv6 classification");
    auto resolved = take(resolve_host("localhost", 443)); require(!resolved.empty() && resolved.front().port == 443, "host resolver");
    require(!resolve_host(std::string("local\0host", 10), 0), "resolver NUL accepted");
    auto inventory = interfaces(); require(!inventory.empty(), "interface inventory empty");
    require(std::any_of(inventory.begin(), inventory.end(), [](const auto& item) { return item.loopback && item.index && !item.name.empty(); }), "interface metadata");
    const auto loop = std::find_if(inventory.begin(), inventory.end(), [](const auto& item) { return item.loopback && item.index; });
    auto interface_name = loop->name;
#ifdef _WIN32
    std::array<char, IF_MAX_STRING_SIZE + 1> native_name{};
    require(if_indextoname(loop->index, native_name.data()) != nullptr, "native interface name lookup");
    interface_name = native_name.data();
#endif
    auto named_scope = take(IpAddress::parse("fe80::1%" + interface_name));
    auto numeric_scope = take(IpAddress::parse("fe80::1%" + std::to_string(loop->index)));
    require(named_scope == numeric_scope && named_scope.scope_id() == loop->index, "IPv6 named scope must retain its native interface index");
    require(!IpAddress::parse("fe80::1%ii-sdk-interface-does-not-exist"), "unknown interface scope accepted");
}
void tcp()
{
    ii::runtime::EventLoop loop;
    for (auto family : {AddressFamily::ipv4, AddressFamily::ipv6})
    {
        Listener listener(loop); ListenerOptions listener_options; listener_options.accepted_socket.stream.allow_half_close = true;
        std::unique_ptr<Tcp> server; listener.accepted = [&](auto stream) { server = std::move(stream); };
        pass(listener.listen(loopback(0, family), listener_options));
        Tcp client(loop); TcpOptions options; options.stream.allow_half_close = true; options.keep_alive = true; options.bind_address = loopback(0, family);
        pass(client.connect(loopback(listener.port(), family), options));
        until(loop, [&] { return server && client.is_connected(); });
        require(client.peer_endpoint()->port == listener.port() && client.local_endpoint()->port && client.peer_endpoint()->address.family() == family, "TCP endpoints");
        pass(client.no_delay(false)); pass(client.keep_alive(false));
        require(client.write("ab\r\nrest"), "TCP framed send");
        until(loop, [&] { return server->available_bytes() == 8; });
        require(server->peek(2) == "ab" && take(server->read_until("\r\n")) == std::optional<std::string>("ab\r\n"), "delimiter read");
        require(!take(server->read_exactly(5)) && take(server->read_exactly(4)) == std::optional<std::string>("rest"), "exact read consumption");
        bool eof = false;
        server->read_closed = [&] { eof = true; require(server->write("reply"), "write after peer half-close"); pass(server->shutdown_write()); };
        pass(client.shutdown_write()); require(!client.write("late"), "write admitted after half-close");
        std::string reply; client.readable = [&] { reply += client.read(); };
        until(loop, [&] { return reply == "reply" && eof && !client.is_connected(); });
        require(client.statistics().written_bytes == 8 && client.statistics().received_bytes == 5, "TCP statistics");
    }
    Listener idle(loop); std::vector<std::unique_ptr<Tcp>> held;
    idle.accepted = [&](auto stream) { held.push_back(std::move(stream)); }; pass(idle.listen(loopback()));
    Tcp client(loop); TcpOptions options; options.stream.idle_timeout = 30ms; bool failed = false;
    client.failed = [&](auto) { failed = true; }; pass(client.connect(loopback(idle.port()), options));
    until(loop, [&] { return failed; }); require(client.state() == SocketState::failed, "idle timeout state");
}
void udp()
{
    ii::runtime::EventLoop loop;
    for (auto family : {AddressFamily::ipv4, AddressFamily::ipv6})
    {
        Udp a(loop), b(loop), stranger(loop); pass(a.bind(loopback(0, family))); pass(b.bind(loopback(0, family))); pass(stranger.bind(loopback(0, family)));
        pass(a.connect_peer(loopback(b.port(), family))); pass(b.connect_peer(loopback(a.port(), family)));
        std::vector<Datagram> received; b.received = [&](auto value) { received.push_back(std::move(value)); };
        pass(stranger.send("ignored", loopback(b.port(), family))); pass(a.write(std::string("x\0y", 3))); pass(a.write(""));
        until(loop, [&] { return received.size() == 2; });
        require(received[0].sender.port == a.port() && received[0].bytes == std::string("x\0y", 3) && received[1].bytes.empty(), "connected UDP filtering/data");
        require(a.statistics().write_operations == 2 && b.statistics().read_operations == 2, "UDP statistics");
        auto binding = a.local_endpoint();
        require(!a.send("wrong peer", loopback(stranger.port(), family)), "connected UDP destination overridden");
        pass(a.disconnect_peer()); require(!a.peer_endpoint() && a.local_endpoint() && a.port() == binding->port &&
            a.local_endpoint()->address.family() == binding->address.family(), "UDP disconnect lost port/family or retained peer");
        pass(a.send("after disconnect", loopback(b.port(), family)));
        until(loop, [&] { return received.size() == 3; }); require(received.back().bytes == "after disconnect", "UDP send after disconnect");
        pass(a.multicast_hops(2)); pass(a.multicast_loopback(true)); require(!a.multicast_hops(256), "invalid multicast hops");
    }
    Udp membership(loop); pass(membership.bind(loopback()));
    auto group = take(IpAddress::parse("239.255.42.42"));
    pass(membership.join_multicast(group)); pass(membership.leave_multicast(group));
    require(!membership.leave_multicast(group), "missing membership left twice");
}
void local()
{
    ii::runtime::EventLoop loop;
    auto path = file("ipc.sock"); std::filesystem::remove(path);
    LocalServer server(loop); std::unique_ptr<LocalSocket> accepted;
    server.accepted = [&](auto stream) { accepted = std::move(stream); };
    pass(server.listen({path})); require(local_entry_exists(path), "local bind entry absent");
    LocalSocket client(loop); pass(client.connect({path})); until(loop, [&] { return accepted && client.is_connected(); });
    require(client.peer_path() == path, "local peer name");
#ifndef _WIN32
    auto identity = client.peer_credentials(); require(identity && identity->user == getuid(), "local peer credentials");
    require((std::filesystem::status(path).permissions() & std::filesystem::perms::others_all) == std::filesystem::perms::none, "local path permissions");
#endif
    require(client.write(std::string("a\0b", 3)), "local send"); until(loop, [&] { return accepted->available_bytes() == 3; });
    require(take(accepted->read_exactly(3)) == std::optional<std::string>(std::string("a\0b", 3)), "local binary receive");
    client.close(); server.close(); require(!local_entry_exists(path), "owned local path not removed");
    auto existing = file("keep.txt"); { std::ofstream output(existing); output << "user data"; }
    require(!server.listen({existing}) && read_file(existing) == "user data", "existing local path overwritten");
    pass(server.listen({path})); auto renamed = file("renamed.sock"); std::filesystem::remove(renamed);
    std::filesystem::rename(path, renamed); { std::ofstream output(path); output << "replacement"; }
    server.close(); require(read_file(path) == "replacement", "replacement local path deleted");
    std::filesystem::remove(path); std::filesystem::remove(renamed);
    require(!client.connect({std::string(LocalSocket::maximum_path_bytes() + 1, 'x')}), "long local path accepted");
    // A callback may destroy the stream that dispatched it.
    pass(server.listen({path})); auto transient = std::make_unique<LocalSocket>(loop); accepted.reset();
    pass(transient->connect({path})); until(loop, [&] { return accepted && transient->is_connected(); });
    transient->readable = [&] { transient.reset(); }; require(accepted->write("destroy"), "local destruction send");
    until(loop, [&] { return !transient; }); server.close();
}
struct TlsServer final
{
    TlsListener listener; std::vector<std::unique_ptr<TlsStream>> clients; unsigned secured = 0, failed = 0;
    explicit TlsServer(ii::runtime::EventLoop& loop, std::shared_ptr<TlsContext> context) : listener(loop, std::move(context))
    {
        listener.accepted = [&](auto stream)
        {
            auto* raw = stream.get(); raw->connected = [&] { ++secured; };
            raw->failed = [&](auto) { ++failed; };
            raw->readable = [raw] { auto bytes = raw->read(); require(raw->write("echo:" + bytes), "TLS echo write"); raw->close(true); };
            clients.push_back(std::move(stream));
        };
        pass(listener.listen(loopback()));
    }
};
void tls()
{
    ii::runtime::EventLoop loop;
    static_assert(!std::copy_constructible<LocalServer> && !std::copy_constructible<TlsListener>);
    TlsStreamOptions invalid_options; invalid_options.handshake_timeout = 0ms;
    TlsListener invalid_listener(loop, take(TlsContext::server(server_options())), invalid_options);
    require(!invalid_listener.listen(loopback()), "invalid TLS listener options admitted");
    auto certificate = take(inspect_certificate_file(file("server.pem")));
    require(certificate.valid_at() && !certificate.valid_at(certificate.valid_until + 1s) &&
        std::find(certificate.dns_names.begin(), certificate.dns_names.end(), "localhost") != certificate.dns_names.end(), "certificate metadata");
    require(!inspect_certificate("bad PEM"), "invalid certificate accepted");
    auto server_policy = server_options(); server_policy.policy.minimum = TlsVersion::tls1_3; server_policy.alpn_protocols = {"iinet/1", "http/1.1"};
    TlsServer server(loop, take(TlsContext::server(server_policy)));
    auto policy = client_options(); policy.alpn_protocols = {"http/1.1", "iinet/1"}; policy.policy.public_key_sha256 = certificate.public_key_sha256;
    TlsStream client(loop, take(TlsContext::client(policy))); std::string reply, error;
    client.connected = [&] { require(client.write(std::string("secret\0payload", 14)), "TLS application write"); };
    client.failed = [&](auto message) { error = message; }; client.readable = [&] { reply += client.read(); };
    pass(client.connect(loopback(server.listener.port()), "localhost"));
    until(loop, [&] { return reply.size() == 19 || !error.empty(); }); require(error.empty() && reply == std::string("echo:secret\0payload", 19), "TLS encrypted roundtrip");
    auto info = client.connection_info(); require(info && info->peer_verified && info->protocol == "TLSv1.3" && info->alpn == "iinet/1" && info->peer_certificate, "TLS negotiated metadata");
    until(loop, [&] { return !client.is_connected(); }); require(error.empty(), "TLS close_notify reported as truncation");
    for (auto mode : {0, 1, 2})
    {
        auto invalid = client_options(); if (mode == 0) invalid.policy.ca_file = file("untrusted.pem");
        if (mode == 2) invalid.policy.public_key_sha256 = std::array<unsigned char, 32>{};
        TlsStream rejected(loop, take(TlsContext::client(invalid))); bool failed = false, connected = false;
        rejected.connected = [&] { connected = true; }; rejected.failed = [&](auto) { failed = true; };
        pass(rejected.connect(loopback(server.listener.port()), mode == 1 ? "wrong.invalid" : "localhost"));
        until(loop, [&] { return failed; }); require(!connected && rejected.tls_state() == TlsState::failed, "invalid TLS peer accepted");
    }
    // QR trust uses an exact, authenticated leaf pin without installing a CA,
    // and temporary private keys never need to be written to disk.
    auto ephemeral = server_options();
    ephemeral.policy.identity = {};
    ephemeral.policy.identity.certificate_chain_pem = read_file(file("server.pem"));
    ephemeral.policy.identity.private_key_pem = read_file(file("server.key"));
    TlsServer pinned_server(loop, take(TlsContext::server(ephemeral)));
    for (bool matches : {true, false})
    {
        TlsOptions trusted; trusted.policy.trusted_certificate_sha256 = certificate.certificate_sha256;
        if (!matches) (*trusted.policy.trusted_certificate_sha256)[0] ^= 1;
        TlsStream pinned(loop, take(TlsContext::client(trusted))); bool secured = false, failed = false;
        pinned.connected = [&] { secured = true; }; pinned.failed = [&](auto) { failed = true; };
        pass(pinned.connect(loopback(pinned_server.listener.port()), "qr-device.invalid"));
        until(loop, [&] { return secured || failed; });
        require(secured == matches && failed != matches, "out-of-band certificate trust ignored");
    }
    auto mixed = ephemeral; mixed.policy.identity.certificate_chain_file = file("server.pem");
    mixed.policy.identity.private_key_file = file("server.key");
    require(!TlsContext::server(mixed), "mixed memory/file TLS identity accepted");
    auto mismatched = ephemeral;
    mismatched.policy.identity.private_key_pem = read_file(file("client.key"));
    require(!TlsContext::server(mismatched), "mismatched memory TLS certificate/key accepted");
    for (const std::string name : {"expired", "client"})
    {
        auto invalid = server_options();
        invalid.policy.identity.certificate_chain_file = file(name + ".pem");
        invalid.policy.identity.private_key_file = file(name == "client" ? "client.key" : "server.key");
        TlsServer invalid_server(loop, take(TlsContext::server(invalid)));
        TlsOptions trusted;
        trusted.policy.trusted_certificate_sha256 = take(inspect_certificate_file(invalid.policy.identity.certificate_chain_file)).certificate_sha256;
        TlsStream rejected(loop, take(TlsContext::client(trusted))); bool connected = false, failed = false;
        rejected.connected = [&] { connected = true; }; rejected.failed = [&](auto) { failed = true; };
        pass(rejected.connect(loopback(invalid_server.listener.port()), "qr-device.invalid"));
        until(loop, [&] { return connected || failed; });
        require(failed && !connected, "exact leaf pin bypassed expiry or certificate purpose");
    }
    auto mutual_policy = server_options(true); TlsServer mutual(loop, take(TlsContext::server(mutual_policy)));
    TlsStream identity(loop, take(TlsContext::client(client_options(true)))); bool ready = false;
    identity.connected = [&] { ready = true; }; pass(identity.connect(loopback(mutual.listener.port()), "localhost"));
    until(loop, [&] { return ready && mutual.secured == 1; });
    require(mutual.clients.back()->connection_info()->peer_verified && mutual.clients.back()->connection_info()->peer_certificate->subject.find("iiNetwork client") != std::string::npos, "mutual TLS identity");
    TlsStream missing(loop, take(TlsContext::client(client_options()))); bool rejected = false;
    missing.failed = [&](auto) { rejected = true; }; pass(missing.connect(loopback(mutual.listener.port()), "localhost"));
    until(loop, [&] { return rejected; }); require(mutual.secured == 1, "missing client certificate secured");
    Listener silent(loop); std::vector<std::unique_ptr<Tcp>> held;
    silent.accepted = [&](auto stream) { held.push_back(std::move(stream)); }; pass(silent.listen(loopback()));
    TlsStreamOptions deadline; deadline.handshake_timeout = 30ms;
    TlsStream timed(loop, take(TlsContext::client(client_options())), deadline); bool expired = false;
    timed.failed = [&](auto) { expired = true; }; pass(timed.connect(loopback(silent.port()), "localhost")); until(loop, [&] { return expired; });
    require(timed.error().find("deadline") != std::string::npos, "TLS handshake deadline");
    // The same TLS stream wraps AF_UNIX and negotiates a restricted TLS 1.2 policy.
    auto local_path = file("tls.sock"); std::filesystem::remove(local_path);
    auto local_server_policy = server_options(); local_server_policy.policy.maximum = TlsVersion::tls1_2;
    auto local_client_policy = client_options(); local_client_policy.policy.maximum = TlsVersion::tls1_2;
    auto server_context = take(TlsContext::server(local_server_policy)), client_context = take(TlsContext::client(local_client_policy));
    LocalServer local_server(loop); std::vector<std::unique_ptr<TlsStream>> local_clients;
    local_server.accepted = [&](auto transport)
    {
        auto secured = std::make_unique<TlsStream>(loop, server_context); auto* raw = secured.get();
        pass(secured->attach(std::move(transport)));
        raw->readable = [raw] { require(raw->write(raw->read()), "local TLS echo"); };
        local_clients.push_back(std::move(secured));
    };
    pass(local_server.listen({local_path})); auto local_transport = std::make_unique<LocalSocket>(loop);
    pass(local_transport->connect({local_path})); until(loop, [&] { return local_transport->is_connected(); });
    TlsStream local_tls(loop, client_context); pass(local_tls.attach(std::move(local_transport), "localhost"));
    until(loop, [&] { return local_tls.is_connected(); });
    require(local_tls.connection_info()->protocol == "TLSv1.2", "TLS 1.2 policy ignored");
    require(local_tls.write("local secret"), "local TLS application send"); until(loop, [&] { return local_tls.available_bytes() == 12; });
    require(local_tls.read() == "local secret", "local TLS plaintext mismatch"); local_tls.close(true);
    until(loop, [&] { return !local_tls.is_connected(); });
    auto doomed_transport = std::make_unique<LocalSocket>(loop); pass(doomed_transport->connect({local_path}));
    until(loop, [&] { return doomed_transport->is_connected(); });
    auto doomed = std::make_unique<TlsStream>(loop, client_context); bool destroyed = false;
    doomed->connected = [&] { doomed.reset(); destroyed = true; }; pass(doomed->attach(std::move(doomed_transport), "localhost"));
    until(loop, [&] { return destroyed; }); local_server.close();
}
void http()
{
    ii::runtime::EventLoop loop; ii::network::HttpServer server(loop);
    require(server.listen(loopback(), [&](const ServerRequest& request)
    {
        ServerResponse result{200, {{"Content-Type", "application/octet-stream"}}, request.body};
        if (request.target == "/cookies")
        { pass(result.header_fields.append("Set-Cookie", "a=1; Path=/")); pass(result.header_fields.append("Set-Cookie", "b=2; Path=/")); result.body = "stored"; }
        else if (request.target == "/cookie") result.body = request.headers.contains("cookie") ? request.headers.at("cookie") : "none";
        else if (request.target == "/auth") result.body = request.headers.contains("authorization") ? request.headers.at("authorization") : "none";
        else if (request.target == "/digest")
        {
            if (!request.headers.contains("authorization"))
            { result.status = 401; result.headers["WWW-Authenticate"] = "Digest realm=\"iiNetwork\", nonce=\"fixture-nonce\", qop=\"auth\", algorithm=MD5"; result.body.clear(); }
            else result.body = request.headers.at("authorization");
        }
        else if (request.target == "/gzip") { result.body = read_file(file("gzip.bin")); result.headers["Content-Encoding"] = "gzip"; }
        else if (request.target == "/fields") result.body = request.headers.at("x-value");
        require(request.peer_endpoint.has_value() && request.local_endpoint.has_value() && !request.secure, "HTTP connection metadata");
        return result;
    }), "HTTP rich server listen");
    Http client(loop); HttpRequest request; request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/cookies";
    request.proxy.type = ProxyType::disabled; request.enable_cookies = true; request.version = HttpVersion::http1_1;
    bool headers = false; request.received_headers = [&](long status, const HeaderFields& fields) { headers = status == 200 && fields.get_all("set-cookie").size() == 2; return true; };
    auto response = exchange(client, loop, request);
    require(response.ok() && headers && response.header_fields.get_all("SET-COOKIE").size() == 2 && response.version == HttpVersion::http1_1 &&
        response.primary_ip == "127.0.0.1" && response.primary_port == server.port() && response.timings.total.count() > 0, "HTTP response metadata/multi-headers");
    require(take(client.cookies()).size() == 2, "cookie jar persistence");
    request.received_headers = {}; request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/cookie";
    require(exchange(client, loop, request).body.find("a=1") != std::string::npos, "cookie resend");
    request.enable_cookies = false; require(exchange(client, loop, request).body == "none", "disabled cookie engine leaked cookie");
    pass(client.clear_cookies()); require(take(client.cookies()).empty() && !client.set_cookie("malformed"), "cookie clear/validation");
    pass(client.set_cookie("127.0.0.1\tFALSE\t/\tFALSE\t0\timported\tvalue")); require(take(client.cookies()).size() == 1, "cookie import");
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/auth";
    request.authentication = {HttpAuthScheme::basic, "user", "pass", {}};
    require(exchange(client, loop, request).body == "Basic dXNlcjpwYXNz", "HTTP basic auth");
    request.authentication = {HttpAuthScheme::bearer, {}, {}, "test-token"};
    require(exchange(client, loop, request).body == "Bearer test-token", "HTTP bearer auth"); request.authentication = {};
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/digest";
    request.authentication = {HttpAuthScheme::digest, "user", "pass", {}};
    response = exchange(client, loop, request);
    require(response.ok() && response.body.starts_with("Digest ") && response.body.find("username=\"user\"") != std::string::npos && response.body.find("response=\"") != std::string::npos, "HTTP Digest negotiation");
    request.authentication = {};
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/upload"; request.set_method(HttpMethod::put);
    std::string upload("a\0b", 3); std::size_t offset = 0; request.upload_size = upload.size();
    request.upload = [&](char* bytes, std::size_t capacity) { auto n = std::min(capacity, upload.size() - offset); std::copy_n(upload.data() + offset, n, bytes); offset += n; return n; };
    response = exchange(client, loop, request); require(response.ok() && response.body == upload && response.transfer.uploaded == upload.size(), "streamed upload");
    offset = 0; request.set_method(HttpMethod::post); require(exchange(client, loop, request).body == upload, "streamed POST upload");
    request.upload = {}; request.upload_size.reset(); request.set_method(HttpMethod::get);
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/gzip"; request.accept_compression = true;
    require(exchange(client, loop, request).body == "compressed response", "HTTP content decompression");
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/fields";
    pass(request.header_fields.append("X-Value", "one")); pass(request.header_fields.append("x-value", "two"));
    require(exchange(client, loop, request).body == "one, two", "HTTP repeated request fields");
    require(!request.header_fields.append("Bad", "injected\r\n"), "header injection accepted");
    auto capabilities = Http::capabilities(); require(capabilities.tls && capabilities.ipv6 && !capabilities.libcurl_version.empty(), "HTTP capability inventory");
    for (bool memory_identity : {false, true})
    {
        auto unsupported = request;
        if (memory_identity) {
            unsupported.tls.identity.certificate_chain_pem = read_file(file("client.pem"));
            unsupported.tls.identity.private_key_pem = read_file(file("client.key"));
        } else unsupported.tls.trusted_certificate_sha256 = std::array<unsigned char, 32>{};
        const auto rejected = client.request(std::move(unsupported), [](auto) {});
        require(!rejected && rejected.error().code == ErrorCode::unsupported, "HTTP silently ignored native-only TLS trust");
    }
    std::cout << "libcurl " << capabilities.libcurl_version << "; TLS=" << capabilities.tls_backend << "; HTTP/2=" << capabilities.http2 << "; HTTP/3=" << capabilities.http3 << '\n';
    if (!capabilities.http3) { auto unavailable = request; unavailable.version = HttpVersion::http3; auto error = client.request(unavailable, [](auto) {}); require(!error && error.error().code == ErrorCode::unsupported, "unsupported HTTP version admitted"); }
    auto invalid_deadline = request; invalid_deadline.inactivity_timeout = std::chrono::milliseconds::max();
    require(!client.request(invalid_deadline, [](auto) {}), "unbounded HTTP deadline accepted");
    auto pinned_redirect = request; pinned_redirect.follow_redirects = true; pinned_redirect.tls.public_key_sha256 = std::array<unsigned char, 32>{};
    require(!client.request(pinned_redirect, [](auto) {}), "automatic redirect with origin-specific pin admitted");
    request.url = "file:///invalid"; require(!client.request(request, [](auto) {}) && client.last_error(), "structured HTTP admission error");
}
void servers()
{
    ii::runtime::EventLoop loop; auto options = server_options(); options.alpn_protocols = {"http/1.1"};
    ii::network::HttpServer https(loop);
    require(https.listen_tls(loopback(), take(TlsContext::server(options)), [](const ServerRequest& request)
    { require(request.secure, "HTTPS request secure flag"); return ServerResponse{200, {{"Content-Type", "text/plain"}}, "secure"}; }), "HTTPS listen");
    Http client(loop); HttpRequest request; request.url = "https://localhost:" + std::to_string(https.port()) + '/';
    request.proxy.type = ProxyType::disabled; request.tls.ca_file = file("ca.pem");
    request.version = HttpVersion::http1_1;
    auto response = exchange(client, loop, request); if (!response.ok()) throw std::runtime_error("HTTPS exchange: " + response.error);
    require(response.body == "secure", "HTTPS payload");
    request.tls.maximum = TlsVersion::tls1_2; require(exchange(client, loop, request).ok(), "HTTPS TLS 1.2 bound");
    request.tls.ca_file = file("untrusted.pem"); response = exchange(client, loop, request); require(!response.ok() && !response.error.empty(), "untrusted HTTPS accepted");
    auto path = file("http.sock"); std::filesystem::remove(path); ii::network::HttpServer local(loop);
    require(local.listen_local({path}, [](const ServerRequest& request)
    {
        require(!request.secure, "local HTTP secure flag");
#ifndef _WIN32
        require(request.local_peer.has_value(), "local HTTP peer metadata");
#endif
        return ServerResponse{200, {}, "local HTTP"};
    }), "local HTTP listen");
    request = {}; request.url = "http://localhost/local"; request.unix_socket_path = path;
    response = exchange(client, loop, request); require(response.ok() && response.body == "local HTTP", "HTTP over local socket");
    local.close(); require(!std::filesystem::exists(path), "HTTP local socket cleanup");
    // A proxy fixture terminates the absolute-form request without external traffic.
    Listener proxy(loop); std::vector<std::unique_ptr<Tcp>> connections; std::string seen;
    proxy.accepted = [&](auto socket)
    {
        auto* raw = socket.get(); raw->readable = [&, raw]
        {
            seen += raw->read(); if (seen.find("\r\n\r\n") == seen.npos) return;
            raw->readable = {}; require(raw->write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy"), "proxy reply"); raw->close(true);
        }; connections.push_back(std::move(socket));
    }; pass(proxy.listen(loopback()));
    request = {}; request.url = "http://example.invalid/resource"; request.proxy.type = ProxyType::http;
    request.proxy.address = "http://127.0.0.1:" + std::to_string(proxy.port());
    response = exchange(client, loop, request);
    require(response.ok() && response.body == "proxy" && seen.starts_with("GET http://example.invalid/resource"), "HTTP explicit proxy");
    Listener chunked(loop); std::vector<std::unique_ptr<Tcp>> chunk_clients;
    chunked.accepted = [&](auto socket)
    {
        auto* raw = socket.get(); auto input = std::make_shared<std::string>(); raw->readable = [raw, input]
        {
            *input += raw->read(); if (input->find("\r\n\r\n") == input->npos) return;
            bool empty = input->starts_with("GET /empty "); raw->readable = {};
            std::string message = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\nConnection: close\r\n\r\n";
            if (!empty) message += "3\r\nabc\r\n";
            message += "0\r\nX-Sum: value\r\n\r\n"; require(raw->write(message), "HTTP trailer fixture write"); raw->close(true);
        }; chunk_clients.push_back(std::move(socket));
    }; pass(chunked.listen(loopback()));
    for (auto target : {"/body", "/empty"})
    {
        request = {}; request.proxy.type = ProxyType::disabled; request.url = "http://127.0.0.1:" + std::to_string(chunked.port()) + target;
        unsigned header_calls = 0; request.received_headers = [&](long, const auto&) { ++header_calls; return true; };
        response = exchange(client, loop, request);
        require(response.ok() && response.trailers.get("x-sum") == std::optional<std::string>("value") && !response.header_fields.contains("x-sum") && header_calls == 1, "HTTP trailers or repeated header callback");
    }
    auto destroy_in_headers = std::make_unique<Http>(loop); bool header_destroyed = false, completed = false;
    request.received_headers = [&](long, const auto&) { destroy_in_headers.reset(); header_destroyed = true; return true; };
    pass(destroy_in_headers->request(request, [&](auto) { completed = true; }));
    until(loop, [&] { return header_destroyed; }); loop.poll(); require(!completed, "completion after destruction in HTTP headers");
}
}
int main(int argc, char** argv)
{
    try
    {
        require(argc == 3, "expected test name and fixture directory"); fixtures = std::filesystem::absolute(argv[2]);
        std::string name = argv[1];
        if (name == "address") addresses(); else if (name == "tcp") tcp(); else if (name == "udp") udp();
        else if (name == "local") local(); else if (name == "tls") tls(); else if (name == "http") http();
        else if (name == "servers") servers(); else throw std::runtime_error("Unknown interface test");
        std::cout << "PASS interfaces." << name << '\n'; return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
