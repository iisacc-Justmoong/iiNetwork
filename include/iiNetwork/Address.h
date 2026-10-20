#pragma once
#include <iiNetwork/Error.h>
#include <array>
#include <compare>
#include <cstdint>
#include <string_view>
#include <vector>

namespace ii::network
{
enum class AddressFamily { any, ipv4, ipv6 };
class IpAddress final
{
  public:
    static Result<IpAddress> parse(std::string_view);
    static IpAddress any(AddressFamily = AddressFamily::ipv4);
    static IpAddress loopback(AddressFamily = AddressFamily::ipv4);
    [[nodiscard]] AddressFamily family() const;
    [[nodiscard]] std::string string() const;
    [[nodiscard]] std::uint32_t scope_id() const;
    [[nodiscard]] const std::array<unsigned char, 16>& bytes() const;
    [[nodiscard]] bool is_unspecified() const;
    [[nodiscard]] bool is_loopback() const;
    [[nodiscard]] bool is_multicast() const;
    [[nodiscard]] bool is_link_local() const;
    auto operator<=>(const IpAddress&) const = default;
  private:
    AddressFamily family_ = AddressFamily::ipv4;
    std::array<unsigned char, 16> bytes_{};
    std::uint32_t scope_ = 0;
};
struct IpEndpoint final
{
    IpAddress address;
    std::uint16_t port = 0;
    static Result<IpEndpoint> parse(std::string_view); // IPv6 requires [address]:port
    [[nodiscard]] std::string string() const;
    auto operator<=>(const IpEndpoint&) const = default;
};
struct IpSubnet final
{
    IpAddress address;
    std::uint8_t prefix_length = 0;
    static Result<IpSubnet> parse(std::string_view);
    [[nodiscard]] bool contains(const IpAddress&) const;
};
// Explicit blocking name-service utility; numeric socket connect never runs DNS.
Result<std::vector<IpEndpoint>> resolve_host(std::string_view host, std::uint16_t port,
                                           AddressFamily = AddressFamily::any);
Result<std::string> reverse_lookup(const IpAddress&);
} // namespace ii::network
