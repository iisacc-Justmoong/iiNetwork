#pragma once
#include <iiNetwork/Transport.h>
#include "ProtocolInternal.h"
#include "PathInternal.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace ii::network::native
{
using namespace std::chrono_literals;
constexpr std::size_t buffer_limit = 513ULL * 1024 * 1024;
#ifdef _WIN32
using Handle = SOCKET;
using Length = int;
constexpr Handle invalid = INVALID_SOCKET;
inline void initialize()
{
    static const int result = [] { WSADATA data{}; return WSAStartup(MAKEWORD(2, 2), &data); }();
    (void)result;
}
inline int last_error() { return WSAGetLastError(); }
inline bool pending(int error) { return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS || error == WSAEALREADY; }
inline void close(Handle fd) { if (fd != invalid) closesocket(fd); }
constexpr int shutdown_send = SD_SEND;
#else
using Handle = int;
using Length = socklen_t;
constexpr Handle invalid = -1;
inline void initialize() {}
inline int last_error() { return errno; }
inline bool pending(int error) { return error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS || error == EALREADY; }
inline void close(Handle fd) { if (fd != invalid) ::close(fd); }
constexpr int shutdown_send = SHUT_WR;
#endif
inline auto failure(std::string operation, int code = last_error())
{ return detail::fail(Layer::transport, ErrorCode::io_error, std::move(operation) + ": " + std::system_category().message(code)); }
inline bool ready(Handle fd, bool writing)
{
#ifdef _WIN32
    fd_set set, errors; FD_ZERO(&set); FD_SET(fd, &set); FD_ZERO(&errors); FD_SET(fd, &errors); timeval timeout{};
    return select(0, writing ? nullptr : &set, writing ? &set : nullptr, &errors, &timeout) > 0;
#else
    pollfd set{fd, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    return ::poll(&set, 1, 0) > 0 && (set.revents & (set.events | POLLERR | POLLHUP | POLLNVAL));
#endif
}
inline int send_flags()
{
#ifdef MSG_NOSIGNAL
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}
inline bool options(Handle fd)
{
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket(fd, FIONBIO, &nonblocking)) return false;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) return false;
#endif
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&one), sizeof(one))) return false;
#endif
    return true;
}
inline int family(AddressFamily family) { return family == AddressFamily::ipv6 ? AF_INET6 : family == AddressFamily::ipv4 ? AF_INET : AF_UNSPEC; }
struct Address
{
    sockaddr_storage storage{};
    Length size = 0;
    sockaddr* data() { return reinterpret_cast<sockaddr*>(&storage); }
    const sockaddr* data() const { return reinterpret_cast<const sockaddr*>(&storage); }
};
inline Address endpoint(IpEndpoint value)
{
    Address out;
    if (value.address.family() == AddressFamily::ipv6)
    {
        auto* a = reinterpret_cast<sockaddr_in6*>(&out.storage); a->sin6_family = AF_INET6;
        a->sin6_port = htons(value.port); a->sin6_scope_id = value.address.scope_id();
        std::memcpy(&a->sin6_addr, value.address.bytes().data(), 16); out.size = sizeof(*a);
    }
    else
    {
        auto* a = reinterpret_cast<sockaddr_in*>(&out.storage); a->sin_family = AF_INET;
        a->sin_port = htons(value.port); std::memcpy(&a->sin_addr, value.address.bytes().data(), 4); out.size = sizeof(*a);
    }
    return out;
}
inline std::optional<IpEndpoint> endpoint(const sockaddr* raw)
{
    std::array<char, INET6_ADDRSTRLEN> text{};
    std::uint16_t port = 0; std::uint32_t scope = 0;
    if (raw->sa_family == AF_INET)
    {
        const auto* a = reinterpret_cast<const sockaddr_in*>(raw); port = ntohs(a->sin_port);
        if (!inet_ntop(AF_INET, &a->sin_addr, text.data(), text.size())) return {};
    }
    else if (raw->sa_family == AF_INET6)
    {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(raw); port = ntohs(a->sin6_port); scope = a->sin6_scope_id;
        if (!inet_ntop(AF_INET6, &a->sin6_addr, text.data(), text.size())) return {};
    }
    else return {};
    std::string literal(text.data()); if (scope) literal += '%' + std::to_string(scope);
    auto address = IpAddress::parse(literal); if (!address) return {};
    return IpEndpoint{*address, port};
}
inline std::optional<IpEndpoint> endpoint(Handle fd, bool peer)
{
    Address raw; raw.size = sizeof(raw.storage);
    auto status = peer ? getpeername(fd, raw.data(), &raw.size) : getsockname(fd, raw.data(), &raw.size);
    return status ? std::nullopt : endpoint(raw.data());
}
inline Result<Address> local_address(std::string_view path, bool abstract)
{
#ifndef __linux__
    if (abstract) return detail::fail(Layer::transport, ErrorCode::unsupported, "Abstract local sockets require Linux");
#endif
    sockaddr_un address{};
    if (path.empty() || path.find('\0') != path.npos || path.size() >= sizeof(address.sun_path))
        return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Local socket path is empty, contains NUL or exceeds the native limit");
    address.sun_family = AF_UNIX;
    Address out;
    if (abstract)
    { std::memcpy(address.sun_path + 1, path.data(), path.size()); out.size = static_cast<Length>(offsetof(sockaddr_un, sun_path) + 1 + path.size()); }
    else
    { std::memcpy(address.sun_path, path.data(), path.size()); out.size = static_cast<Length>(offsetof(sockaddr_un, sun_path) + path.size() + 1); }
#ifdef __APPLE__
    address.sun_len = static_cast<unsigned char>(out.size);
#endif
    std::memcpy(&out.storage, &address, sizeof(address)); return out;
}
inline std::string local_name(Handle fd, bool peer)
{
    sockaddr_un address{}; Length length = sizeof(address);
    if ((peer ? getpeername(fd, reinterpret_cast<sockaddr*>(&address), &length) :
                getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length)) || address.sun_family != AF_UNIX) return {};
    auto count = length > offsetof(sockaddr_un, sun_path) ? std::min<std::size_t>(length - offsetof(sockaddr_un, sun_path), sizeof(address.sun_path)) : 0;
    if (!count) return {};
    if (!address.sun_path[0]) return count > 1 ? "@" + std::string(address.sun_path + 1, count - 1) : std::string{};
    return std::string(address.sun_path, std::find(address.sun_path, address.sun_path + count, '\0'));
}
inline std::optional<PeerCredentials> credentials(Handle fd)
{
#ifdef __APPLE__
    uid_t user; gid_t group;
    if (getpeereid(fd, &user, &group)) return {};
    return PeerCredentials{user, group, {}};
#elif defined(__linux__)
    struct ucred identity{}; Length size = sizeof(identity);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &identity, &size)) return {};
    return PeerCredentials{identity.uid, identity.gid, static_cast<std::uint64_t>(identity.pid)};
#else
    (void)fd; return {};
#endif
}
struct LocalBinding
{
    std::string path;
    std::uint64_t device = 0, inode = 0;
    bool remove_on_close = true;
    static std::optional<std::pair<std::uint64_t, std::uint64_t>> identity(const std::string& path)
    {
#ifdef _WIN32
        auto native = detail::utf8_path(path).wstring();
        HANDLE handle = CreateFileW(native.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return {};
        BY_HANDLE_FILE_INFORMATION info{}; bool ok = GetFileInformationByHandle(handle, &info); CloseHandle(handle);
        if (!ok) return {};
        return std::pair<std::uint64_t, std::uint64_t>{info.dwVolumeSerialNumber, (std::uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow};
#else
        struct stat value{};
        if (lstat(path.c_str(), &value) || !S_ISSOCK(value.st_mode)) return {};
        return std::pair<std::uint64_t, std::uint64_t>{value.st_dev, value.st_ino};
#endif
    }
    void remember(std::string name, bool remove)
    {
        path = std::move(name); remove_on_close = remove;
        if (auto id = identity(path)) { device = id->first; inode = id->second; }
    }
    void cleanup()
    {
        if (!path.empty() && remove_on_close)
            if (auto id = identity(path); id && id->first == device && id->second == inode)
            { std::error_code error; std::filesystem::remove(detail::utf8_path(path), error); }
        path.clear(); device = inode = 0;
    }
};
inline Result<void> validate(const StreamOptions& options)
{
    if (options.receive_bytes > buffer_limit || options.pending_bytes > buffer_limit ||
        options.connect_timeout.count() <= 0 || options.idle_timeout.count() < 0 ||
        options.connect_timeout > std::chrono::hours(24 * 365) || options.idle_timeout > std::chrono::hours(24 * 365))
        return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Invalid stream limits or deadline (maximum one year)");
    return {};
}
} // namespace ii::network::native
