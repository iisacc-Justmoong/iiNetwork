#include <iiNetwork/Address.h>
#include "SocketInternal.h"
#include <charconv>
#include <set>

namespace ii::network
{
Result<IpAddress> IpAddress::parse(std::string_view text)
{
    native::initialize();
    if (text.empty() || text.size() > 256 || text.find('\0') != text.npos)
        return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid IP literal");
    IpAddress result;
    std::string literal(text);
    auto percent = literal.find('%');
    if (percent != literal.npos)
    {
        auto scope = std::string_view(literal).substr(percent + 1);
        if (scope.empty()) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Empty IPv6 scope");
        auto [end, error] = std::from_chars(scope.data(), scope.data() + scope.size(), result.scope_);
        if (error != std::errc{} || end != scope.data() + scope.size()) result.scope_ = if_nametoindex(std::string(scope).c_str());
        if (!result.scope_) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Unknown IPv6 scope");
        literal.resize(percent);
    }
    if (inet_pton(AF_INET6, literal.c_str(), result.bytes_.data()) == 1) result.family_ = AddressFamily::ipv6;
    else
    {
        result.bytes_.fill(0);
        if (percent != text.npos || inet_pton(AF_INET, literal.c_str(), result.bytes_.data()) != 1)
            return detail::fail(Layer::network, ErrorCode::invalid_argument, "Expected an IPv4 or IPv6 literal");
    }
    return result;
}
IpAddress IpAddress::any(AddressFamily family) { IpAddress out; out.family_ = family == AddressFamily::ipv6 ? family : AddressFamily::ipv4; return out; }
IpAddress IpAddress::loopback(AddressFamily family)
{
    auto out = any(family);
    if (out.family_ == AddressFamily::ipv6) out.bytes_[15] = 1;
    else { out.bytes_[0] = 127; out.bytes_[3] = 1; }
    return out;
}
AddressFamily IpAddress::family() const { return family_; }
const std::array<unsigned char, 16>& IpAddress::bytes() const { return bytes_; }
std::uint32_t IpAddress::scope_id() const { return scope_; }
std::string IpAddress::string() const
{
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (!inet_ntop(native::family(family_), bytes_.data(), text.data(), text.size())) return {};
    return std::string(text.data()) + (scope_ ? '%' + std::to_string(scope_) : "");
}
bool IpAddress::is_unspecified() const
{ return std::all_of(bytes_.begin(), bytes_.begin() + (family_ == AddressFamily::ipv4 ? 4 : 16), [](auto b) { return b == 0; }); }
bool IpAddress::is_loopback() const { return family_ == AddressFamily::ipv4 ? bytes_[0] == 127 : bytes_ == loopback(AddressFamily::ipv6).bytes_; }
bool IpAddress::is_multicast() const { return family_ == AddressFamily::ipv4 ? (bytes_[0] & 0xf0) == 0xe0 : bytes_[0] == 0xff; }
bool IpAddress::is_link_local() const { return family_ == AddressFamily::ipv4 ? bytes_[0] == 169 && bytes_[1] == 254 : bytes_[0] == 0xfe && (bytes_[1] & 0xc0) == 0x80; }
Result<IpEndpoint> IpEndpoint::parse(std::string_view text)
{
    std::string_view host, port;
    if (text.starts_with('['))
    {
        auto bracket = text.find(']');
        if (bracket == text.npos || bracket + 1 >= text.size() || text[bracket + 1] != ':')
            return detail::fail(Layer::network, ErrorCode::invalid_argument, "Expected [IPv6]:port");
        host = text.substr(1, bracket - 1); port = text.substr(bracket + 2);
    }
    else
    {
        auto colon = text.find(':');
        if (colon == text.npos) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Expected IPv4:port");
        host = text.substr(0, colon); port = text.substr(colon + 1);
    }
    auto address = IpAddress::parse(host); unsigned number = 0;
    if (!address || port.empty()) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid endpoint address or port");
    auto [end, error] = std::from_chars(port.data(), port.data() + port.size(), number);
    if (error != std::errc{} || end != port.data() + port.size() || number > 65535)
        return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid endpoint port");
    return IpEndpoint{*address, static_cast<std::uint16_t>(number)};
}
std::string IpEndpoint::string() const
{ return (address.family() == AddressFamily::ipv6 ? '[' + address.string() + ']' : address.string()) + ':' + std::to_string(port); }
Result<IpSubnet> IpSubnet::parse(std::string_view text)
{
    auto slash = text.find('/');
    if (slash == text.npos) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Expected address/prefix");
    auto address = IpAddress::parse(text.substr(0, slash)); auto prefix = text.substr(slash + 1); unsigned count = 0;
    if (!address || prefix.empty()) return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid subnet");
    auto [end, error] = std::from_chars(prefix.data(), prefix.data() + prefix.size(), count);
    if (error != std::errc{} || end != prefix.data() + prefix.size() || count > (address->family() == AddressFamily::ipv4 ? 32U : 128U))
        return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid subnet prefix length");
    return IpSubnet{*address, static_cast<std::uint8_t>(count)};
}
bool IpSubnet::contains(const IpAddress& other) const
{
    if (address.family() != other.family() || prefix_length > (address.family() == AddressFamily::ipv4 ? 32 : 128)) return false;
    for (unsigned bit = 0; bit < prefix_length; ++bit)
        if ((address.bytes()[bit / 8] ^ other.bytes()[bit / 8]) & (128U >> (bit % 8))) return false;
    return !address.scope_id() || address.scope_id() == other.scope_id();
}
Result<std::vector<IpEndpoint>> resolve_host(std::string_view host, std::uint16_t port, AddressFamily family)
{
    native::initialize();
    if (host.empty() || host.size() > 253 || host.find('\0') != host.npos)
        return detail::fail(Layer::network, ErrorCode::invalid_argument, "Invalid resolver host");
    addrinfo hints{}; hints.ai_family = native::family(family); hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw = nullptr; auto service = std::to_string(port);
    int code = getaddrinfo(std::string(host).c_str(), service.c_str(), &hints, &raw);
    if (code) return detail::fail(Layer::network, ErrorCode::io_error, "Name resolution failed: " + std::to_string(code));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(raw, freeaddrinfo);
    std::vector<IpEndpoint> results; std::set<IpEndpoint> seen;
    for (auto* item = raw; item && results.size() < 256; item = item->ai_next)
        if (auto value = native::endpoint(item->ai_addr); value && seen.insert(*value).second) results.push_back(*value);
    if (results.empty()) return detail::fail(Layer::network, ErrorCode::unavailable, "Resolver returned no IP endpoints");
    return results;
}
Result<std::string> reverse_lookup(const IpAddress& ip)
{
    auto address = native::endpoint(IpEndpoint{ip, 0}); std::array<char, NI_MAXHOST> text{};
    int code = getnameinfo(address.data(), address.size, text.data(), text.size(), nullptr, 0, NI_NAMEREQD);
    if (code) return detail::fail(Layer::network, ErrorCode::io_error, "Reverse name resolution failed: " + std::to_string(code));
    return std::string(text.data());
}
} // namespace ii::network
