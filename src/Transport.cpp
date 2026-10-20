#include <iiNetwork/Transport.h>
#include "SocketInternal.h"
#include <deque>
#include <map>
#include <utility>
#ifdef _WIN32
#include <iphlpapi.h>
#endif

namespace ii::network
{
using namespace std::chrono_literals;
using native::Handle;
using native::invalid;
namespace
{
auto argument(std::string message) { return detail::fail(Layer::transport, ErrorCode::invalid_argument, std::move(message)); }
Result<void> socket_option(Handle fd, int level, int name, int value)
{
    if (setsockopt(fd, level, name, reinterpret_cast<const char*>(&value), sizeof(value))) return native::failure("setsockopt");
    return {};
}
Result<void> tcp_options(Handle fd, const TcpOptions& options, bool local)
{
    auto valid = native::validate(options.stream); if (!valid) return valid;
    if ((options.send_buffer_bytes && *options.send_buffer_bytes <= 0) || (options.receive_buffer_bytes && *options.receive_buffer_bytes <= 0))
        return argument("Socket buffer sizes must be positive");
    if (fd == invalid) return {};
    if (!local)
    {
        auto result = socket_option(fd, IPPROTO_TCP, TCP_NODELAY, options.no_delay); if (!result) return result;
        result = socket_option(fd, SOL_SOCKET, SO_KEEPALIVE, options.keep_alive); if (!result) return result;
    }
    if (options.send_buffer_bytes) { auto result = socket_option(fd, SOL_SOCKET, SO_SNDBUF, *options.send_buffer_bytes); if (!result) return result; }
    if (options.receive_buffer_bytes) return socket_option(fd, SOL_SOCKET, SO_RCVBUF, *options.receive_buffer_bytes);
    return {};
}
std::uint8_t prefix_bits(const sockaddr* address)
{
    if (!address) return 0;
    const unsigned char* bytes = address->sa_family == AF_INET ? reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(address)->sin_addr) :
        reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr);
    unsigned count = 0;
    for (unsigned i = 0; i < (address->sa_family == AF_INET ? 4U : 16U); ++i)
        for (unsigned bit = 0; bit < 8; ++bit) if (bytes[i] & (128U >> bit)) ++count;
    return static_cast<std::uint8_t>(count);
}
}
std::vector<Interface> interfaces()
{
    native::initialize(); std::vector<Interface> result;
#ifdef _WIN32
    ULONG size = 16384; std::vector<unsigned char> memory(size);
    auto* first = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(memory.data());
    auto flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    auto code = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, first, &size);
    if (code == ERROR_BUFFER_OVERFLOW)
    { memory.resize(size); first = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(memory.data()); code = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, first, &size); }
    if (code != NO_ERROR) return result;
    for (auto* a = first; a; a = a->Next)
        if (a->OperStatus == IfOperStatusUp)
            for (auto* u = a->FirstUnicastAddress; u; u = u->Next)
                if (auto endpoint = native::endpoint(u->Address.lpSockaddr))
                {
                    auto family = endpoint->address.family(); auto prefix = std::min<unsigned>(u->OnLinkPrefixLength, family == AddressFamily::ipv4 ? 32 : 128);
                    result.push_back({endpoint->address.string(), family == AddressFamily::ipv4 && prefix ? 0xffffffffU << (32 - prefix) : 0,
                        a->IfType == IF_TYPE_SOFTWARE_LOOPBACK, (a->Flags & IP_ADAPTER_NO_MULTICAST) == 0,
                        a->AdapterName, family == AddressFamily::ipv4 ? a->IfIndex : a->Ipv6IfIndex, family, static_cast<std::uint8_t>(prefix)});
                }
#else
    ifaddrs* first = nullptr; if (getifaddrs(&first)) return result;
    for (auto* a = first; a; a = a->ifa_next)
    {
        if (!a->ifa_addr || (a->ifa_addr->sa_family != AF_INET && a->ifa_addr->sa_family != AF_INET6) || !(a->ifa_flags & IFF_UP)) continue;
        auto endpoint = native::endpoint(a->ifa_addr); if (!endpoint) continue;
        auto family = endpoint->address.family(); auto prefix = prefix_bits(a->ifa_netmask);
        result.push_back({endpoint->address.string(), family == AddressFamily::ipv4 && prefix ? 0xffffffffU << (32 - prefix) : 0,
            (a->ifa_flags & IFF_LOOPBACK) != 0, (a->ifa_flags & IFF_MULTICAST) != 0,
            a->ifa_name, if_nametoindex(a->ifa_name), family, prefix});
    }
    freeifaddrs(first);
#endif
    return result;
}
bool ipv4(std::string_view text) { auto ip = IpAddress::parse(text); return ip && ip->family() == AddressFamily::ipv4; }
bool ipv6(std::string_view text) { auto ip = IpAddress::parse(text); return ip && ip->family() == AddressFamily::ipv6; }
bool own_address(std::string_view text)
{
    auto address = IpAddress::parse(text); if (!address) return false;
    for (const auto& local : interfaces()) if (auto ip = IpAddress::parse(local.address); ip && *ip == *address) return true;
    return false;
}
bool local_address(std::string_view text)
{
    auto address = IpAddress::parse(text);
    if (!address || address->is_unspecified() || address->is_multicast() || text == "255.255.255.255") return false;
    if (address->is_loopback()) return true;
    for (const auto& local : interfaces())
        if (auto ip = IpAddress::parse(local.address); ip && local.prefix_length && IpSubnet{*ip, local.prefix_length}.contains(*address)) return true;
    return false;
}
struct Tcp::Impl
{
    struct State
    {
        Handle fd = invalid; runtime::TaskToken tick; Tcp* owner;
        TcpOptions options; SocketState state = SocketState::closed;
        bool alive = true, local = false, read_open = true, write_open = true, shutdown_pending = false;
        std::string incoming, error, peer_name, local_name;
        std::optional<IpEndpoint> local_endpoint, peer_endpoint;
        StreamStatistics statistics;
        struct Pending { std::shared_ptr<const std::string> bytes; std::size_t offset = 0; };
        std::deque<Pending> outgoing; std::size_t queued = 0;
        runtime::Clock::time_point started{}, last_activity{}, close_deadline{};
        explicit State(Tcp* value) : owner(value) {}
        void capture()
        {
            local_endpoint = native::endpoint(fd, false); peer_endpoint = native::endpoint(fd, true);
            local_name = local ? native::local_name(fd, false) : local_endpoint ? local_endpoint->address.string() : "";
            peer_name = local ? native::local_name(fd, true) : peer_endpoint ? peer_endpoint->address.string() : peer_name;
        }
        void finish(std::string message = {})
        {
            if (fd == invalid) return;
            native::close(std::exchange(fd, invalid)); tick.cancel(); outgoing.clear(); queued = 0;
            state = message.empty() ? SocketState::closed : SocketState::failed; error = std::move(message);
            auto failure = owner->failed;
            auto disconnect = owner->disconnected;
            if (!error.empty() && failure) failure(error);
            if (alive && disconnect) disconnect();
        }
        void pump()
        {
            if (!alive || fd == invalid) return;
            auto now = runtime::Clock::now();
            if (state == SocketState::connecting)
            {
                if (now - started >= options.stream.connect_timeout) { finish("TCP/local connection deadline elapsed"); return; }
                if (!native::ready(fd, true)) return;
                int code = 0; native::Length length = sizeof(code);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&code), &length) || code)
                { finish(std::system_category().message(code ? code : native::last_error())); return; }
                state = SocketState::connected; last_activity = now; capture();
                auto callback = owner->connected; if (callback) callback();
                if (!alive || fd == invalid) return;
            }
            if (options.stream.idle_timeout.count() && now - last_activity >= options.stream.idle_timeout)
            { finish("Stream idle deadline elapsed"); return; }
            if (!outgoing.empty() && native::ready(fd, true))
            {
                auto& front = outgoing.front(); auto count = std::min<std::size_t>(front.bytes->size() - front.offset, 256 * 1024);
                int n = static_cast<int>(::send(fd, front.bytes->data() + front.offset, static_cast<int>(count), native::send_flags()));
                if (n > 0)
                {
                    front.offset += n; queued -= n; statistics.written_bytes += n; ++statistics.write_operations; last_activity = now;
                    if (front.offset == front.bytes->size()) outgoing.pop_front();
                    auto written = owner->bytes_written; if (written) written(n);
                    if (!alive || fd == invalid) return;
                    if (!queued) { auto callback = owner->drained; if (callback) callback(); }
                    if (!alive || fd == invalid) return;
                }
                else if (n < 0 && !native::pending(native::last_error())) { finish(std::system_category().message(native::last_error())); return; }
            }
            if (shutdown_pending && outgoing.empty() && write_open)
            {
                if (::shutdown(fd, native::shutdown_send)) { finish(std::system_category().message(native::last_error())); return; }
                write_open = false;
                if (!read_open) { finish(); return; }
            }
            if (state == SocketState::closing && (outgoing.empty() || now >= close_deadline)) { finish(); return; }
            if (read_open && native::ready(fd, false))
            {
                std::array<char, 65536> bytes{}; int n = static_cast<int>(::recv(fd, bytes.data(), bytes.size(), 0));
                if (!n)
                {
                    read_open = false;
                    if (!options.stream.allow_half_close || !write_open) { finish(); return; }
                    auto callback = owner->read_closed; if (callback) callback(); return;
                }
                if (n < 0) { if (!native::pending(native::last_error())) finish(std::system_category().message(native::last_error())); return; }
                if (incoming.size() > options.stream.receive_bytes || static_cast<std::size_t>(n) > options.stream.receive_bytes - incoming.size())
                { finish("Receive limit exceeded"); return; }
                incoming.append(bytes.data(), n); statistics.received_bytes += n; ++statistics.read_operations; last_activity = now;
                auto callback = owner->readable; if (callback) callback();
            }
        }
    };
    runtime::EventLoop& loop;
    std::shared_ptr<State> state;
    Impl(runtime::EventLoop& value, Tcp* owner) : loop(value), state(std::make_shared<State>(owner)) { native::initialize(); }
    bool start()
    {
        state->tick = loop.every(5ms, [weak = std::weak_ptr<State>(state)] { if (auto keep = weak.lock()) keep->pump(); }).token;
        return state->tick.pending();
    }
    Result<void> connect(native::Address address, TcpOptions options, bool local)
    {
        auto valid = tcp_options(invalid, options, local); if (!valid) return valid;
        auto& s = *state; s.options = std::move(options); s.local = local;
        s.incoming.clear(); s.error.clear(); s.statistics = {}; s.read_open = s.write_open = true; s.shutdown_pending = false;
        s.local_endpoint.reset(); s.peer_endpoint.reset(); s.local_name.clear(); s.peer_name.clear();
        s.fd = ::socket(address.storage.ss_family, SOCK_STREAM, 0);
        auto reject = [&](Error failure) -> Result<void>
        { s.error = failure.message; s.state = SocketState::failed; native::close(std::exchange(s.fd, invalid)); return std::unexpected(std::move(failure)); };
        if (s.fd == invalid || !native::options(s.fd)) return reject(native::failure("socket/nonblocking").error());
        auto configured = tcp_options(s.fd, s.options, local); if (!configured) return reject(configured.error());
        if (s.options.bind_address && !local)
        {
            auto source = native::endpoint(*s.options.bind_address);
            if (source.storage.ss_family != address.storage.ss_family) return reject(argument("Local bind address family differs from peer").error());
            if (::bind(s.fd, source.data(), source.size)) return reject(native::failure("bind").error());
        }
        auto status = ::connect(s.fd, address.data(), address.size);
        if (status && !native::pending(native::last_error())) return reject(native::failure("connect").error());
        s.state = SocketState::connecting; s.started = s.last_activity = runtime::Clock::now();
        if (!start()) return reject(Error{ErrorCode::unavailable, Layer::transport, "Core stream dispatch admission failed"});
        return {};
    }
};
Tcp::Tcp(runtime::EventLoop& loop) : p_(std::make_unique<Impl>(loop, this)) {}
Tcp::~Tcp() { p_->state->alive = false; close(); }
bool Tcp::connect(std::string_view address, std::uint16_t port)
{ auto ip = IpAddress::parse(address); return ip && connect(IpEndpoint{*ip, port}).has_value(); }
Result<void> Tcp::connect(IpEndpoint endpoint) { return connect(endpoint, p_->state->options); }
Result<void> Tcp::connect(IpEndpoint endpoint, TcpOptions options) { close(); return p_->connect(native::endpoint(endpoint), std::move(options), false); }
Result<void> Tcp::connect_local(std::string_view path, bool abstract, StreamOptions options)
{
    auto address = native::local_address(path, abstract); if (!address) return std::unexpected(address.error());
    close(); TcpOptions configuration; configuration.stream = options; return p_->connect(*address, configuration, true);
}
Result<void> Tcp::configure(TcpOptions options)
{ auto valid = tcp_options(p_->state->fd, options, p_->state->local); if (valid) p_->state->options = std::move(options); return valid; }
Result<void> Tcp::no_delay(bool value) { auto options = p_->state->options; options.no_delay = value; return configure(std::move(options)); }
Result<void> Tcp::keep_alive(bool value) { auto options = p_->state->options; options.keep_alive = value; return configure(std::move(options)); }
bool Tcp::write(std::string_view bytes) { return write(std::make_shared<const std::string>(bytes)); }
bool Tcp::write(std::shared_ptr<const std::string> bytes)
{
    auto& s = *p_->state;
    if (!bytes || s.state != SocketState::connected || !s.write_open || s.shutdown_pending || s.queued > s.options.stream.pending_bytes ||
        bytes->size() > s.options.stream.pending_bytes - s.queued || s.outgoing.size() >= 1024) return false;
    if (bytes->empty()) return true;
    s.queued += bytes->size(); s.outgoing.push_back({std::move(bytes), 0}); return true;
}
std::string Tcp::read() { return std::exchange(p_->state->incoming, {}); }
std::string Tcp::read_some(std::size_t maximum)
{ auto& bytes = p_->state->incoming; auto count = std::min(maximum, bytes.size()); auto out = bytes.substr(0, count); bytes.erase(0, count); return out; }
std::string Tcp::peek(std::size_t maximum) const { return p_->state->incoming.substr(0, maximum); }
std::size_t Tcp::available_bytes() const { return p_->state->incoming.size(); }
void Tcp::close(bool flush)
{
    auto& s = *p_->state;
    if (flush && s.state == SocketState::connected && !s.outgoing.empty())
    { s.state = SocketState::closing; s.close_deadline = runtime::Clock::now() + 1s; return; }
    s.tick.cancel(); native::close(std::exchange(s.fd, invalid)); s.state = SocketState::closed;
    s.outgoing.clear(); s.queued = 0; s.read_open = s.write_open = false;
}
Result<void> Tcp::shutdown_write()
{
    auto& s = *p_->state;
    if (s.state != SocketState::connected || !s.write_open || s.shutdown_pending) return detail::fail(Layer::transport, ErrorCode::invalid_state, "Stream write side is not open");
    s.shutdown_pending = true; return {};
}
bool Tcp::is_connected() const { return p_->state->state == SocketState::connected || p_->state->state == SocketState::closing; }
SocketState Tcp::state() const { return p_->state->state; }
std::string Tcp::peer_address() const { return p_->state->peer_name; }
std::string Tcp::local_name(bool peer) const { return peer ? p_->state->peer_name : p_->state->local_name; }
std::string Tcp::error() const { return p_->state->error; }
void Tcp::receive_limit(std::size_t value) { p_->state->options.stream.receive_bytes = std::min(value, native::buffer_limit); }
void Tcp::send_limit(std::size_t value) { p_->state->options.stream.pending_bytes = std::min(value, native::buffer_limit); }
std::size_t Tcp::pending_bytes() const { return p_->state->queued; }
StreamStatistics Tcp::statistics() const { return p_->state->statistics; }
std::optional<IpEndpoint> Tcp::local_endpoint() const { return p_->state->local_endpoint; }
std::optional<IpEndpoint> Tcp::peer_endpoint() const { return p_->state->peer_endpoint; }
std::optional<PeerCredentials> Tcp::peer_credentials() const { return p_->state->local && p_->state->fd != invalid ? native::credentials(p_->state->fd) : std::nullopt; }
struct Listener::Impl
{
    runtime::EventLoop& loop; Handle fd = invalid; runtime::TaskToken tick; Listener* owner;
    std::string error, path; std::optional<IpEndpoint> endpoint; ListenerOptions options;
    native::LocalBinding binding; bool alive = true, local = false;
    Impl(runtime::EventLoop& value, Listener* parent) : loop(value), owner(parent) { native::initialize(); }
    void close() { tick.cancel(); native::close(std::exchange(fd, invalid)); binding.cleanup(); endpoint.reset(); path.clear(); }
};
Listener::Listener(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop, this)) {}
Listener::~Listener() { p_->alive = false; close(); }
bool Listener::listen(std::uint16_t port) { return listen("0.0.0.0", port); }
bool Listener::listen(std::string_view address, std::uint16_t port)
{ auto ip = IpAddress::parse(address); return ip && listen(IpEndpoint{*ip, port}).has_value(); }
Result<void> Listener::listen(IpEndpoint endpoint, ListenerOptions options)
{
    close(); auto& p = *p_; p.error.clear(); p.local = false; p.options = std::move(options);
    if (p.options.backlog <= 0 || p.options.backlog > 65535) return argument("Invalid TCP listen backlog");
    auto valid = tcp_options(invalid, p.options.accepted_socket, false); if (!valid) return valid;
    auto address = native::endpoint(endpoint); p.fd = ::socket(address.storage.ss_family, SOCK_STREAM, 0);
    if (p.fd == invalid || !native::options(p.fd)) { auto failure = native::failure("socket/nonblocking"); p.error = failure.error().message; close(); return failure; }
    auto configured = socket_option(p.fd, SOL_SOCKET, SO_REUSEADDR, p.options.reuse_address);
    if (configured && endpoint.address.family() == AddressFamily::ipv6) configured = socket_option(p.fd, IPPROTO_IPV6, IPV6_V6ONLY, p.options.ipv6_only);
    if (!configured || ::bind(p.fd, address.data(), address.size) || ::listen(p.fd, p.options.backlog))
    { auto failure = configured ? native::failure("bind/listen") : std::unexpected(configured.error()); p.error = failure.error().message; close(); return failure; }
    p.endpoint = native::endpoint(p.fd, false);
    p.tick = p.loop.every(5ms, [weak = std::weak_ptr<Impl>(p_)]
    {
        auto keep = weak.lock(); if (!keep) return; auto& p = *keep;
        for (unsigned i = 0; i < 16 && p.alive && p.fd != invalid && native::ready(p.fd, false); ++i)
        {
            auto fd = ::accept(p.fd, nullptr, nullptr); if (fd == invalid) break;
            if (!native::options(fd)) { native::close(fd); continue; }
            auto stream = std::make_unique<Tcp>(p.loop); auto& s = *stream->p_->state;
            s.fd = fd; s.local = p.local; s.options = p.options.accepted_socket; s.state = SocketState::connected;
            s.started = s.last_activity = runtime::Clock::now(); s.capture();
            if (!tcp_options(fd, s.options, p.local) || !stream->p_->start()) continue;
            auto callback = p.owner->accepted; if (callback) callback(std::move(stream));
        }
    }).token;
    if (!p.tick.pending()) { close(); return detail::fail(Layer::transport, ErrorCode::unavailable, "Core listener dispatch admission failed"); }
    return {};
}
Result<void> Listener::listen_local(std::string_view path, bool abstract, int backlog, StreamOptions stream, unsigned permissions, bool remove)
{
    // Reuse the same accepted-stream pump; only address setup differs.
    close(); auto& p = *p_; p.error.clear(); p.local = true;
    if (backlog <= 0 || backlog > 65535 || (permissions & ~0777U)) return argument("Invalid local listener options");
    auto valid = native::validate(stream); if (!valid) return valid;
    auto address = native::local_address(path, abstract); if (!address) return std::unexpected(address.error());
    p.options = {}; p.options.backlog = backlog; p.options.accepted_socket.stream = stream;
    p.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (p.fd == invalid || !native::options(p.fd) || ::bind(p.fd, address->data(), address->size))
    { auto failure = native::failure("local bind"); p.error = failure.error().message; close(); return failure; }
    p.path = std::string(path);
    if (!abstract) p.binding.remember(p.path, remove);
#ifndef _WIN32
    if (!abstract && ::chmod(p.path.c_str(), permissions))
    { auto failure = native::failure("local socket permissions"); p.error = failure.error().message; close(); return failure; }
#endif
    if (::listen(p.fd, backlog)) { auto failure = native::failure("local listen"); p.error = failure.error().message; close(); return failure; }
    p.tick = p.loop.every(5ms, [weak = std::weak_ptr<Impl>(p_)]
    {
        auto keep = weak.lock(); if (!keep) return; auto& p = *keep;
        for (unsigned i = 0; i < 16 && p.alive && p.fd != invalid && native::ready(p.fd, false); ++i)
        {
            auto fd = ::accept(p.fd, nullptr, nullptr); if (fd == invalid) break;
            if (!native::options(fd)) { native::close(fd); continue; }
            auto client = std::make_unique<Tcp>(p.loop); auto& s = *client->p_->state;
            s.fd = fd; s.local = true; s.options = p.options.accepted_socket; s.state = SocketState::connected;
            s.started = s.last_activity = runtime::Clock::now(); s.capture();
            if (!client->p_->start()) continue;
            auto callback = p.owner->accepted; if (callback) callback(std::move(client));
        }
    }).token;
    if (!p.tick.pending()) { close(); return detail::fail(Layer::transport, ErrorCode::unavailable, "Core local listener dispatch admission failed"); }
    return {};
}
void Listener::close() { p_->close(); }
std::uint16_t Listener::port() const { return p_->endpoint ? p_->endpoint->port : 0; }
std::optional<IpEndpoint> Listener::local_endpoint() const { return p_->endpoint; }
std::string Listener::error() const { return p_->error; }
std::string Listener::local_path() const { return p_->path; }
struct Udp::Impl
{
    runtime::EventLoop& loop; Handle fd = invalid; runtime::TaskToken tick; Udp* owner;
    UdpOptions options; std::optional<IpEndpoint> local, bound, peer; std::string error, group;
    bool alive = true, include_loopback = false; std::vector<Interface> routes;
    std::vector<std::pair<IpAddress, std::uint32_t>> memberships; StreamStatistics statistics;
    Impl(runtime::EventLoop& value, Udp* parent) : loop(value), owner(parent) { native::initialize(); }
    Result<void> membership(IpAddress group, std::uint32_t index, bool join)
    {
        if (fd == invalid || !local) return detail::fail(Layer::transport, ErrorCode::invalid_state, "UDP socket is not bound");
        if (!group.is_multicast() || group.family() != local->address.family()) return argument("Multicast group family mismatch");
        int code;
        if (group.family() == AddressFamily::ipv6)
        {
            ipv6_mreq request{}; std::memcpy(&request.ipv6mr_multiaddr, group.bytes().data(), 16);
            request.ipv6mr_interface = index ? index : group.scope_id();
            code = setsockopt(fd, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, reinterpret_cast<const char*>(&request), sizeof(request));
        }
        else
        {
            ip_mreq request{}; std::memcpy(&request.imr_multiaddr, group.bytes().data(), 4);
            if (index)
            {
                bool found = false;
                for (const auto& interface : interfaces()) if (interface.index == index && interface.family == AddressFamily::ipv4)
                { auto address = IpAddress::parse(interface.address); if (address) { std::memcpy(&request.imr_interface, address->bytes().data(), 4); found = true; break; } }
                if (!found) return argument("Unknown IPv4 multicast interface index");
            }
            code = setsockopt(fd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, reinterpret_cast<const char*>(&request), sizeof(request));
        }
        if (code) { auto failure = native::failure("multicast membership"); error = failure.error().message; return failure; }
        return {};
    }
};
Udp::Udp(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop, this)) {}
Udp::~Udp() { p_->alive = false; close(); }
bool Udp::bind(std::string_view address, std::uint16_t port)
{ auto ip = IpAddress::parse(address); return ip && bind(IpEndpoint{*ip, port}).has_value(); }
Result<void> Udp::bind(IpEndpoint endpoint, UdpOptions options)
{
    close(); auto& p = *p_; p.error.clear(); p.options = options; p.statistics = {};
    if (options.multicast_hops > 255 || options.maximum_datagram_bytes > 65527) return argument("Invalid UDP size or multicast hop limit");
    auto address = native::endpoint(endpoint); p.fd = ::socket(address.storage.ss_family, SOCK_DGRAM, 0);
    if (p.fd == invalid || !native::options(p.fd)) { auto failure = native::failure("UDP socket/nonblocking"); p.error = failure.error().message; close(); return failure; }
    auto configured = socket_option(p.fd, SOL_SOCKET, SO_REUSEADDR, options.reuse_address);
    if (configured && endpoint.address.family() == AddressFamily::ipv6) configured = socket_option(p.fd, IPPROTO_IPV6, IPV6_V6ONLY, options.ipv6_only);
    if (!configured || ::bind(p.fd, address.data(), address.size))
    { auto failure = configured ? native::failure("UDP bind") : std::unexpected(configured.error()); p.error = failure.error().message; close(); return failure; }
    p.local = native::endpoint(p.fd, false); p.bound = p.local;
    configured = broadcast(options.broadcast);
    if (configured) configured = multicast_hops(options.multicast_hops);
    if (configured) configured = multicast_loopback(options.multicast_loopback);
    if (!configured) { close(); return configured; }
    if (!start_receiving()) return detail::fail(Layer::transport, ErrorCode::unavailable, p.error);
    return {};
}
bool Udp::start_receiving()
{
    p_->tick = p_->loop.every(5ms, [weak = std::weak_ptr<Impl>(p_)]
    {
        auto keep = weak.lock(); if (!keep) return; auto& p = *keep;
        for (unsigned i = 0; i < 64 && p.alive && p.fd != invalid && native::ready(p.fd, false); ++i)
        {
            std::array<char, 65536> bytes{}; native::Address sender; sender.size = sizeof(sender.storage);
            int count = static_cast<int>(recvfrom(p.fd, bytes.data(), bytes.size(), 0, sender.data(), &sender.size));
            if (count < 0) break;
            auto endpoint = native::endpoint(sender.data()); if (!endpoint) continue;
            if (static_cast<std::size_t>(count) > p.options.maximum_datagram_bytes)
            { p.error = "UDP datagram exceeds receive bound"; auto failure = p.owner->failed; if (failure) failure(p.error); continue; }
            p.statistics.received_bytes += count; ++p.statistics.read_operations;
            auto callback = p.owner->received;
            if (callback) callback({std::string(bytes.data(), count), endpoint->address.string(), endpoint->port, *endpoint});
        }
    }).token;
    if (!p_->tick.pending()) { p_->error = "Core UDP dispatch admission failed"; close(); return false; }
    return true;
}
bool Udp::bind_multicast(std::string_view group, std::uint16_t port, bool loopback)
{
    auto ip = IpAddress::parse(group); if (!ip || !ip->is_multicast()) return false;
    UdpOptions options; options.reuse_address = true;
    if (!bind({IpAddress::any(ip->family()), port}, options)) return false;
    p_->group = std::string(group); p_->include_loopback = loopback;
    if (!refresh_interfaces()) { close(); return false; } return true;
}
Result<void> Udp::join_multicast(IpAddress group, std::uint32_t index)
{
    auto key = std::pair(group, index); if (std::find(p_->memberships.begin(), p_->memberships.end(), key) != p_->memberships.end()) return {};
    auto result = p_->membership(group, index, true); if (result) p_->memberships.push_back(key); return result;
}
Result<void> Udp::leave_multicast(IpAddress group, std::uint32_t index)
{
    auto key = std::pair(group, index); auto found = std::find(p_->memberships.begin(), p_->memberships.end(), key);
    if (found == p_->memberships.end()) return argument("Multicast membership is not registered");
    auto result = p_->membership(group, index, false); if (result) p_->memberships.erase(found); return result;
}
bool Udp::refresh_interfaces()
{
    auto& p = *p_; if (p.fd == invalid) return false; if (p.group.empty()) return true;
    auto group = IpAddress::parse(p.group); if (!group) return false;
    auto current = interfaces(); std::erase_if(current, [&](const auto& item)
    { return item.family != group->family() || (item.loopback && !p.include_loopback) || (!item.multicast && !item.loopback); });
    std::vector<Interface> joined;
    for (const auto& old : p.routes)
        if (std::none_of(current.begin(), current.end(), [&](const auto& item) { return item.index == old.index; })) (void)leave_multicast(*group, old.index);
    for (const auto& item : current)
        if (std::none_of(joined.begin(), joined.end(), [&](const auto& other) { return item.index == other.index; }) && join_multicast(*group, item.index)) joined.push_back(item);
    p.routes = std::move(joined); if (p.routes.empty()) p.error = "No multicast interface is available"; else p.error.clear();
    return !p.routes.empty();
}
Result<void> Udp::connect_peer(IpEndpoint endpoint)
{
    if (!p_->local || endpoint.address.family() != p_->local->address.family() || !endpoint.port) return argument("UDP peer requires a matching bound family and nonzero port");
    auto address = native::endpoint(endpoint);
    if (::connect(p_->fd, address.data(), address.size)) return native::failure("UDP connect");
    p_->peer = endpoint; p_->local = native::endpoint(p_->fd, false); return {};
}
Result<void> Udp::disconnect_peer()
{
    if (p_->fd == invalid) return detail::fail(Layer::transport, ErrorCode::closed, "UDP socket is closed");
#ifdef __APPLE__
    if (::disconnectx(p_->fd, SAE_ASSOCID_ANY, SAE_CONNID_ANY)) return native::failure("UDP disconnect");
#else
    auto address = native::endpoint({IpAddress::any(p_->local->address.family()), 0}); address.data()->sa_family = AF_UNSPEC;
    if (::connect(p_->fd, address.data(), address.size)) return native::failure("UDP disconnect");
#endif
    p_->peer.reset(); p_->local = native::endpoint(p_->fd, false);
    // Some kernels unbind a UDP socket when AF_UNSPEC removes its peer.
    if (p_->bound && (!p_->local || !p_->local->port))
    {
        auto binding = native::endpoint(*p_->bound);
        if (::bind(p_->fd, binding.data(), binding.size)) return native::failure("UDP rebind after disconnect");
        p_->local = native::endpoint(p_->fd, false);
    }
    return {};
}
Result<void> Udp::send(std::string_view bytes, IpEndpoint endpoint)
{
    auto& p = *p_;
    if (p.fd == invalid || !p.local) return detail::fail(Layer::transport, ErrorCode::closed, "UDP socket is closed");
    if (endpoint.address.family() != p.local->address.family() || !endpoint.port) return argument("UDP destination family or port is invalid");
    if (p.peer && *p.peer != endpoint) return argument("Connected UDP sends must target its peer; disconnect before selecting another destination");
    auto maximum = endpoint.address.family() == AddressFamily::ipv4 ? 65507U : 65527U;
    if (bytes.size() > maximum || bytes.size() > p.options.maximum_datagram_bytes) return detail::fail(Layer::transport, ErrorCode::too_large, "UDP datagram limit exceeded");
    auto address = native::endpoint(endpoint);
    int count = static_cast<int>(p.peer ? ::send(p.fd, bytes.data(), static_cast<int>(bytes.size()), native::send_flags()) :
        sendto(p.fd, bytes.data(), static_cast<int>(bytes.size()), native::send_flags(), address.data(), address.size));
    if (count != static_cast<int>(bytes.size())) return native::failure("UDP send");
    p.statistics.written_bytes += count; ++p.statistics.write_operations; return {};
}
bool Udp::send(std::string_view bytes, std::string_view address, std::uint16_t port)
{
    auto ip = IpAddress::parse(address); if (!ip) return false;
    if (address == p_->group && !p_->routes.empty())
    {
        bool sent = false;
        for (const auto& item : p_->routes)
        {
            if (ip->family() == AddressFamily::ipv6) { auto index = item.index; setsockopt(p_->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<const char*>(&index), sizeof(index)); }
            else if (auto source = IpAddress::parse(item.address)) setsockopt(p_->fd, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char*>(source->bytes().data()), 4);
            if (send(bytes, {*ip, port})) sent = true;
        }
        return sent;
    }
    return send(bytes, {*ip, port}).has_value();
}
Result<void> Udp::write(std::string_view bytes)
{ if (!p_->peer) return detail::fail(Layer::transport, ErrorCode::invalid_state, "UDP socket has no connected peer"); return send(bytes, *p_->peer); }
Result<void> Udp::broadcast(bool enabled)
{
    if (!p_->local) return detail::fail(Layer::transport, ErrorCode::closed, "UDP socket is closed");
    if (p_->local->address.family() == AddressFamily::ipv6) return enabled ? Result<void>(argument("IPv6 has no broadcast")) : Result<void>{};
    auto result = socket_option(p_->fd, SOL_SOCKET, SO_BROADCAST, enabled); if (result) p_->options.broadcast = enabled; return result;
}
Result<void> Udp::multicast_hops(unsigned hops)
{
    if (!p_->local || hops > 255) return argument("Invalid multicast hop limit or unbound UDP socket");
    Result<void> result;
    if (p_->local->address.family() == AddressFamily::ipv6) result = socket_option(p_->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, static_cast<int>(hops));
    else { auto value = static_cast<unsigned char>(hops); if (setsockopt(p_->fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&value), sizeof(value))) result = native::failure("multicast TTL"); }
    if (result) p_->options.multicast_hops = hops; return result;
}
Result<void> Udp::multicast_loopback(bool enabled)
{
    if (!p_->local) return detail::fail(Layer::transport, ErrorCode::closed, "UDP socket is closed");
    Result<void> result;
    if (p_->local->address.family() == AddressFamily::ipv6) result = socket_option(p_->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, enabled);
    else { auto value = static_cast<unsigned char>(enabled); if (setsockopt(p_->fd, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&value), sizeof(value))) result = native::failure("multicast loopback"); }
    if (result) p_->options.multicast_loopback = enabled; return result;
}
void Udp::close()
{ p_->tick.cancel(); native::close(std::exchange(p_->fd, invalid)); p_->local.reset(); p_->bound.reset(); p_->peer.reset(); p_->memberships.clear(); p_->routes.clear(); p_->group.clear(); }
std::string Udp::error() const { return p_->error; }
std::uint16_t Udp::port() const { return p_->local ? p_->local->port : 0; }
std::optional<IpEndpoint> Udp::local_endpoint() const { return p_->local; }
std::optional<IpEndpoint> Udp::peer_endpoint() const { return p_->peer; }
StreamStatistics Udp::statistics() const { return p_->statistics; }
} // namespace ii::network
