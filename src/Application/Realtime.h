#pragma once
#include <iiNetwork/Presentation.h>
#include <iiNetwork/Session.h>
#include <iiNetwork/Transport.h>
#include <vector>

namespace ii::network
{
using RealtimePeerId = std::uint64_t;
enum class RealtimeState { closed, connecting, ready, failed };

struct RealtimeLimits final
{
    std::size_t peers = 64, channels = 16, payload_bytes = 1024;
    std::size_t pending_frames = 128, pending_bytes = 128 * 1024;
    std::size_t bytes_per_second = 128 * 1024, packets_per_second = 2048;
    std::size_t packets_per_tick = 64;
    std::chrono::milliseconds tick_interval{5}, retry_interval{100};
    std::chrono::milliseconds heartbeat_interval{250}, idle_timeout{5000};
    std::chrono::milliseconds handshake_timeout{3000}, maximum_frame_age{250};
};

// A single-use, per-participant credential. Deliver through authenticated TLS
// or trusted IPC; never place its key in a URL, public lobby or log.
struct RealtimeTicket final
{
    SessionId id;
    RealtimePeerId peer = 0;
    std::string room;
    Aes256Gcm::Key key{};
};
struct RealtimePeerInfo final
{
    RealtimePeerId peer = 0;
    std::string room;
    IpEndpoint endpoint;
    std::chrono::microseconds round_trip_time{0};
};
struct RealtimeFrame final
{
    RealtimePeerId peer = 0; // Zero identifies an application/server publication.
    std::string room;
    std::uint16_t channel = 0;
    std::uint64_t sequence = 0;
    std::string bytes;
};
struct RealtimeStatistics final
{
    std::uint64_t sent_packets = 0, received_packets = 0;
    std::uint64_t sent_bytes = 0, received_bytes = 0;
    std::uint64_t sent_frames = 0, received_frames = 0, coalesced_frames = 0;
    std::uint64_t rejected_packets = 0, stale_frames = 0, expired_frames = 0;
    std::uint64_t backpressure = 0, sequence_gaps = 0, congestion_events = 0;
    // Gaps are observations, not a measurement of permanent packet loss.
    std::chrono::microseconds round_trip_time{0};
    std::size_t send_rate_bytes_per_second = 0;
};

// Native, encrypted UDP latest-value channels. No application/game schema or
// simulation policy is imposed. All methods/callbacks belong to the host loop.
class RealtimeServer final
{
  public:
    explicit RealtimeServer(runtime::EventLoop&);
    ~RealtimeServer();
    RealtimeServer(const RealtimeServer&) = delete;
    RealtimeServer& operator=(const RealtimeServer&) = delete;
    std::function<void(RealtimePeerInfo)> connected;
    std::function<void(RealtimePeerInfo, Error)> disconnected;
    std::function<void(RealtimeFrame)> received;

    Result<void> listen(IpEndpoint = {IpAddress::loopback(), 0}, RealtimeLimits = {});
    Result<RealtimeTicket> issue(std::string room,
        std::chrono::milliseconds lifetime = std::chrono::seconds(30));
    Result<std::uint64_t> send(RealtimePeerId, std::uint16_t channel, std::string bytes);
    Result<std::size_t> broadcast(std::string_view room, std::uint16_t channel,
                                 std::string bytes, RealtimePeerId except = 0);
    // Explicit host policy: forward authenticated input to the same room,
    // excluding its source, while preserving its authenticated peer/sequence.
    Result<std::size_t> relay(const RealtimeFrame&);
    bool revoke(RealtimePeerId);
    void close();
    [[nodiscard]] bool listening() const;
    [[nodiscard]] std::uint16_t port() const;
    [[nodiscard]] std::vector<RealtimePeerInfo> peers() const;
    [[nodiscard]] std::size_t pending_tickets() const;
    [[nodiscard]] std::size_t pending_bytes() const;
    [[nodiscard]] RealtimeStatistics statistics() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};

class RealtimeClient final
{
  public:
    explicit RealtimeClient(runtime::EventLoop&);
    ~RealtimeClient();
    RealtimeClient(const RealtimeClient&) = delete;
    RealtimeClient& operator=(const RealtimeClient&) = delete;
    std::function<void()> connected, disconnected;
    std::function<void(Error)> failed;
    std::function<void(RealtimeFrame)> received;

    Result<void> connect(IpEndpoint server, const RealtimeTicket&, RealtimeLimits = {});
    // Replaces unsent data on this channel. Loss/reordering never waits for an
    // obsolete frame; reliable commands use Peer/TLS alongside this data plane.
    Result<std::uint64_t> publish(std::uint16_t channel, std::string bytes);
    void close();
    [[nodiscard]] RealtimeState state() const;
    [[nodiscard]] std::optional<RealtimePeerInfo> info() const;
    [[nodiscard]] std::optional<Error> error() const;
    [[nodiscard]] std::optional<IpEndpoint> local_endpoint() const;
    [[nodiscard]] std::size_t pending_bytes() const;
    [[nodiscard]] RealtimeStatistics statistics() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
