#include <iiNetwork/ByteStream.h>
#include "ProtocolInternal.h"

namespace ii::network
{
bool ByteStream::write(std::shared_ptr<const std::string> bytes) { return bytes && write(std::string_view(*bytes)); }
Result<void> ByteStream::shutdown_write() { return detail::fail(Layer::transport, ErrorCode::unsupported, "This stream does not support half-close"); }
std::optional<IpEndpoint> ByteStream::local_endpoint() const { return {}; }
std::optional<IpEndpoint> ByteStream::peer_endpoint() const { return {}; }
std::optional<PeerCredentials> ByteStream::peer_credentials() const { return {}; }
Result<std::optional<std::string>> ByteStream::read_exactly(std::size_t count)
{
    if (available_bytes() < count)
    {
        if (!is_connected()) return detail::fail(Layer::transport, ErrorCode::closed, "Stream closed before the requested byte count");
        return std::optional<std::string>{};
    }
    return std::optional<std::string>(read_some(count));
}
Result<std::optional<std::string>> ByteStream::read_until(std::string_view delimiter, std::size_t maximum)
{
    if (delimiter.empty() || maximum < delimiter.size()) return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Invalid delimiter or frame bound");
    auto bytes = peek(maximum); auto found = bytes.find(delimiter);
    if (found != bytes.npos) return std::optional<std::string>(read_some(found + delimiter.size()));
    if (available_bytes() >= maximum) return detail::fail(Layer::transport, ErrorCode::too_large, "Delimited frame exceeds its bound");
    if (!is_connected()) return detail::fail(Layer::transport, ErrorCode::closed, "Stream closed before a delimiter");
    return std::optional<std::string>{};
}
} // namespace ii::network
