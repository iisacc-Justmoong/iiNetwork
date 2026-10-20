#pragma once
#include <iiNetwork/Error.h>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace ii::network
{
class HeaderFields final
{
  public:
    Result<void> append(std::string name, std::string value);
    Result<void> set(std::string name, std::string value);
    std::size_t remove(std::string_view name);
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
    [[nodiscard]] std::vector<std::string> get_all(std::string_view name) const;
    [[nodiscard]] bool contains(std::string_view name) const;
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& entries() const;
    [[nodiscard]] std::size_t size() const;
    void clear();
  private:
    std::vector<std::pair<std::string, std::string>> entries_;
};
} // namespace ii::network
