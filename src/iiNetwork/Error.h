#pragma once
#include <expected>
#include <string>

namespace ii::network
{
enum class Layer { physical = 1, data_link, network, transport, session, presentation, application };
enum class ErrorCode
{
    invalid_argument, malformed, checksum_mismatch, too_large, unsupported, unavailable,
    would_block, closed, no_route, ttl_expired, invalid_state, expired, replay,
    authentication_failed, io_error, cancelled, not_found, permission_denied, remote_error
};
struct Error final
{
    ErrorCode code;
    Layer layer;
    std::string message;
};
template <class T> using Result = std::expected<T, Error>;
} // namespace ii::network
