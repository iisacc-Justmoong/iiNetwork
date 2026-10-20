#pragma once
#include "ProtocolInternal.h"
#include <iiNetwork/Http.h>

namespace ii::network::detail
{
inline bool token(std::string_view text)
{
    if (text.empty()) return false;
    for (unsigned char c : text)
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos))
            return false;
    return true;
}
inline bool header_value(std::string_view text)
{
    for (unsigned char c : text) if ((c < 32 && c != '\t') || c == 127) return false;
    return true;
}
bool http_url(std::string_view);
bool http_request(const HttpRequest&);
} // namespace ii::network::detail
