#pragma once
#include <filesystem>
#include <string_view>

namespace ii::network::detail
{
inline std::filesystem::path utf8_path(std::string_view text)
{ return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size())); }
}
