#pragma once
#include <iiNetwork/Address.h>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <optional>

namespace ii::network
{
enum class SocketState { closed, connecting, connected, closing, failed };
struct StreamOptions final
{
    std::size_t receive_bytes = 513ULL * 1024 * 1024, pending_bytes = 513ULL * 1024 * 1024;
    std::chrono::milliseconds connect_timeout{10000}, idle_timeout{0};
    bool allow_half_close = false;
};
struct StreamStatistics final
{
    std::uint64_t received_bytes = 0, written_bytes = 0, read_operations = 0, write_operations = 0;
};
struct PeerCredentials final
{
    std::optional<std::uint64_t> user, group, process;
};
// Owner-thread, nonblocking, bounded byte stream. Callbacks run on the Core loop.
class ByteStream
{
  public:
    virtual ~ByteStream() = default;
    std::function<void()> connected, readable, disconnected, drained, read_closed;
    std::function<void(std::size_t)> bytes_written;
    std::function<void(std::string)> failed;
    virtual bool write(std::string_view) = 0;
    virtual bool write(std::shared_ptr<const std::string>);
    [[nodiscard]] virtual std::string read() = 0;
    [[nodiscard]] virtual std::string read_some(std::size_t) = 0;
    [[nodiscard]] virtual std::string peek(std::size_t maximum = std::numeric_limits<std::size_t>::max()) const = 0;
    [[nodiscard]] virtual std::size_t available_bytes() const = 0;
    [[nodiscard]] virtual std::size_t pending_bytes() const = 0;
    virtual void receive_limit(std::size_t) = 0;
    virtual void send_limit(std::size_t) = 0;
    virtual void close(bool flush = false) = 0;
    virtual Result<void> shutdown_write();
    [[nodiscard]] virtual bool is_connected() const = 0;
    [[nodiscard]] virtual SocketState state() const = 0;
    [[nodiscard]] virtual std::string error() const = 0;
    [[nodiscard]] virtual StreamStatistics statistics() const = 0;
    [[nodiscard]] virtual std::optional<IpEndpoint> local_endpoint() const;
    [[nodiscard]] virtual std::optional<IpEndpoint> peer_endpoint() const;
    [[nodiscard]] virtual std::optional<PeerCredentials> peer_credentials() const;
    Result<std::optional<std::string>> read_exactly(std::size_t);
    Result<std::optional<std::string>> read_until(std::string_view delimiter, std::size_t maximum = 65536);
};
} // namespace ii::network
