#include <iiNetwork/Wire.h>
#include <random>
#include <array>
#include <stdexcept>
namespace ii::network::wire
{
std::string uuid()
{
    std::random_device random;
    std::array<unsigned char, 16> bytes{};
    for (auto& b : bytes)
        b = static_cast<unsigned char>(random());
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            result += '-';
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}
std::string base64(std::string_view input)
{
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    unsigned bits = 0, value = 0;
    for (unsigned char b : input)
    {
        value = (value << 8) | b;
        bits += 8;
        while (bits >= 6)
        {
            bits -= 6;
            output += alphabet[(value >> bits) & 63];
        }
    }
    if (bits)
        output += alphabet[(value << (6 - bits)) & 63];
    while (output.size() % 4)
        output += '=';
    return output;
}
std::optional<std::string> percent_decode(std::string_view input)
{
    std::string output;
    output.reserve(input.size());
    auto hex = [](char c) -> int
    {
        return c >= '0' && c <= '9'   ? c - '0'
               : c >= 'a' && c <= 'f' ? c - 'a' + 10
               : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                      : -1;
    };
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        if (input[i] != '%')
        {
            output += input[i];
            continue;
        }
        if (input.size() - i < 3)
            return {};
        int hi = hex(input[i + 1]), lo = hex(input[i + 2]);
        if (hi < 0 || lo < 0)
            return {};
        output += static_cast<char>(hi * 16 + lo);
        i += 2;
    }
    return output;
}
std::optional<std::string> unbase64(std::string_view input, bool url)
{
    std::string output;
    unsigned bits = 0, value = 0;
    bool padded = false;
    std::size_t pads = 0;
    for (char c : input)
    {
        if (c == '=')
        {
            padded = true;
            ++pads;
            if (pads > 2)
                return {};
            continue;
        }
        if (padded)
            return {};
        int digit = c >= 'A' && c <= 'Z'     ? c - 'A'
                    : c >= 'a' && c <= 'z'   ? c - 'a' + 26
                    : c >= '0' && c <= '9'   ? c - '0' + 52
                    : c == (url ? '-' : '+') ? 62
                    : c == (url ? '_' : '/') ? 63
                                             : -1;
        if (digit < 0)
            return {};
        value = (value << 6) | static_cast<unsigned>(digit);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            output += static_cast<char>((value >> bits) & 255);
        }
    }
    const auto required_pads = bits == 4 ? 2U : bits == 2 ? 1U : 0U;
    if (bits >= 6 || (bits && (value & ((1U << bits) - 1))) ||
        ((!url || pads) && (input.size() % 4 || pads != required_pads)))
        return {};
    return output;
}
void append_be(std::string& out, std::uint64_t n, std::size_t size)
{
    if (size > 8) throw std::invalid_argument("Big-endian field width exceeds uint64_t");
    for (std::size_t i = size; i; --i)
        out += static_cast<char>((n >> ((i - 1) * 8)) & 255);
}
bool take_be(std::string_view& in, std::uint64_t& n, std::size_t size)
{
    if (size > 8 || in.size() < size)
        return false;
    n = 0;
    for (unsigned char c : in.substr(0, size))
        n = (n << 8) | c;
    in.remove_prefix(size);
    return true;
}
} // namespace ii::network::wire
