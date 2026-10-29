#pragma once
#include <iiNetwork/Error.h>
#include <cstdint>
#include <string_view>

namespace ii::network::detail
{
inline std::unexpected<Error> fail(Layer layer, ErrorCode code, std::string message)
{ return std::unexpected(Error{code, layer, std::move(message)}); }
inline unsigned byte(std::string_view bytes, std::size_t i)
{ return static_cast<unsigned char>(bytes[i]); }
inline std::uint16_t u16(std::string_view bytes, std::size_t i)
{ return static_cast<std::uint16_t>((byte(bytes, i) << 8) | byte(bytes, i + 1)); }
inline std::uint32_t u32(std::string_view bytes, std::size_t i)
{ return (std::uint32_t(u16(bytes, i)) << 16) | u16(bytes, i + 2); }
inline void put16(std::string& out, std::uint16_t value)
{ out += static_cast<char>(value >> 8); out += static_cast<char>(value); }
inline void put32(std::string& out, std::uint32_t value)
{ put16(out, static_cast<std::uint16_t>(value >> 16)); put16(out, static_cast<std::uint16_t>(value)); }
inline std::uint16_t checksum(std::string_view bytes)
{
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < bytes.size(); i += 2)
    {
        sum += std::uint32_t(byte(bytes, i)) << 8;
        if (i + 1 < bytes.size()) sum += byte(bytes, i + 1);
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}
} // namespace ii::network::detail
