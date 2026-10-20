#pragma once
#include <iiJson/Json.h>
#include <algorithm>
#include <cmath>
#include <cctype>
#include <optional>
#include <string>
namespace ii::network::wire
{
using Value = ii::core::Value;
using Object = Value::Object;
using Array = Value::Array;
inline const Value& field(const Object& object, std::string_view key)
{
    static const Value missing;
    const auto found = object.find(key);
    return found == object.end() ? missing : found->second;
}
inline const Value& field(const Value& value, std::string_view key)
{
    auto p = value.get<Object>();
    static const Value missing;
    return p ? field(p->get(), key) : missing;
}
inline std::string text(const Value& v)
{
    auto p = v.get<std::string>();
    return p ? p->get() : std::string{};
}
inline bool boolean(const Value& v, bool fallback = false)
{
    auto p = v.get<bool>();
    return p ? p->get() : fallback;
}
inline double number(const Value& v, double fallback = 0)
{
    return std::visit(
        [fallback](const auto& x) -> double
        {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_arithmetic_v<T> && !std::is_same_v<T, bool>)
                return static_cast<double>(x);
            else
                return fallback;
        },
        v.storage());
}
inline Object object(const Value& v)
{
    auto p = v.get<Object>();
    return p ? p->get() : Object{};
}
inline Array array(const Value& v)
{
    auto p = v.get<Array>();
    return p ? p->get() : Array{};
}
inline bool unicode_space(char32_t c)
{
    return (c >= 9 && c <= 13) || c == 32 || c == 0x85 || c == 0xa0 || c == 0x1680 ||
           (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f ||
           c == 0x205f || c == 0x3000;
}
inline std::pair<char32_t, std::size_t> codepoint(std::string_view s, std::size_t offset)
{
    auto first = static_cast<unsigned char>(s[offset]);
    std::size_t width = first < 128 ? 1 : first < 224 ? 2 : first < 240 ? 3 : 4;
    if (width > s.size() - offset)
        return {0xfffd, 1};
    char32_t c = first & (width == 1 ? 127 : width == 2 ? 31 : width == 3 ? 15 : 7);
    for (std::size_t i = 1; i < width; ++i)
        c = (c << 6) | (static_cast<unsigned char>(s[offset + i]) & 63);
    return {c, width};
}
inline std::string trim(std::string s)
{
    std::size_t begin = 0, end = 0;
    for (std::size_t i = 0; i < s.size();)
    {
        auto [c, width] = codepoint(s, i);
        if (!unicode_space(c))
        {
            if (!end)
                begin = i;
            end = i + width;
        }
        i += width;
    }
    return end ? s.substr(begin, end - begin) : std::string{};
}

inline std::string lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z')
            c += 32;
    return s;
}
inline bool canonical_uuid(std::string_view s)
{
    if (s.size() != 36 || s == "00000000-0000-0000-0000-000000000000")
        return false;
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (s[i] != '-')
                return false;
        }
        else if (!std::isxdigit(static_cast<unsigned char>(s[i])))
            return false;
    }
    return true;
}
std::string uuid();
inline std::string json(const Value& v, std::size_t limit = 8 * 1024 * 1024)
{
    ii::json::Limits limits;
    limits.output_bytes = limit;
    auto result = ii::json::stringify(v, limits);
    return result ? std::move(*result) : std::string{};
}
inline std::optional<Value> parse_json(std::string_view s, std::size_t limit = 8 * 1024 * 1024)
{
    ii::json::Limits limits;
    limits.input_bytes = limit;
    auto result = ii::json::parse(s, limits);
    if (!result)
        return {};
    return std::move(*result);
}
std::string base64(std::string_view);
std::optional<std::string> percent_decode(std::string_view);
std::optional<std::string> unbase64(std::string_view, bool url = false);
void append_be(std::string&, std::uint64_t, std::size_t);
bool take_be(std::string_view&, std::uint64_t&, std::size_t);
} // namespace ii::network::wire
