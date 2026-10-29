#include <iiNetwork/Headers.h>
#include "HttpInternal.h"
#include <algorithm>

namespace ii::network
{
namespace
{
bool equal(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    { auto fold = [](char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }; if (fold(a[i]) != fold(b[i])) return false; }
    return true;
}
}
Result<void> HeaderFields::append(std::string name, std::string value)
{
    std::size_t bytes = name.size() + value.size();
    for (const auto& entry : entries_) bytes += entry.first.size() + entry.second.size();
    if (entries_.size() >= 128 || bytes > 65536) return detail::fail(Layer::application, ErrorCode::too_large, "HTTP header field limit exceeded");
    if (!detail::token(name) || !detail::header_value(value)) return detail::fail(Layer::application, ErrorCode::invalid_argument, "Invalid HTTP field name or value");
    entries_.emplace_back(std::move(name), std::move(value)); return {};
}
Result<void> HeaderFields::set(std::string name, std::string value)
{
    auto copy = *this; copy.remove(name); auto result = copy.append(std::move(name), std::move(value));
    if (result) *this = std::move(copy); return result;
}
std::size_t HeaderFields::remove(std::string_view name) { return std::erase_if(entries_, [&](const auto& entry) { return equal(entry.first, name); }); }
std::optional<std::string> HeaderFields::get(std::string_view name) const
{ for (const auto& entry : entries_) if (equal(entry.first, name)) return entry.second; return {}; }
std::vector<std::string> HeaderFields::get_all(std::string_view name) const
{ std::vector<std::string> values; for (const auto& entry : entries_) if (equal(entry.first, name)) values.push_back(entry.second); return values; }
bool HeaderFields::contains(std::string_view name) const { return get(name).has_value(); }
const std::vector<std::pair<std::string, std::string>>& HeaderFields::entries() const { return entries_; }
std::size_t HeaderFields::size() const { return entries_.size(); }
void HeaderFields::clear() { entries_.clear(); }
} // namespace ii::network
