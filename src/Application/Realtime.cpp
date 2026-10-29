#include <iiNetwork/Realtime.h>
#include <iiNetwork/Wire.h>
#include "ProtocolInternal.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <list>
#include <map>

namespace ii::network
{
namespace
{
using Clock = runtime::Clock;
using namespace std::chrono_literals;
constexpr auto layer = Layer::application;
constexpr std::size_t datagram_limit = 1200, header_size = 32;
constexpr std::uint64_t packet_limit = 1ULL << 24;
enum class Kind : unsigned char { join = 1, welcome, data, ping, pong, bye };
enum class Reason : unsigned char { closed = 0, revoked = 1, expired = 2 };
Error make_error(ErrorCode code, std::string text) { return {code, layer, std::move(text)}; }
auto fail(ErrorCode code, std::string text) { return std::unexpected(make_error(code, std::move(text))); }
bool nil(SessionId id) { return std::all_of(id.bytes.begin(), id.bytes.end(), [](auto b) { return b == 0; }); }
bool room_valid(std::string_view room) { return !room.empty() && room.size() <= 128 && room.find('\0') == room.npos; }
bool endpoint_valid(IpEndpoint endpoint)
{
    return endpoint.port && !endpoint.address.is_unspecified() && !endpoint.address.is_multicast() &&
           endpoint.address.string() != "255.255.255.255";
}
Result<void> validate(const RealtimeLimits& l)
{
    if (!l.peers || l.peers > 1024 || !l.channels || l.channels > 256 ||
        !l.payload_bytes || l.payload_bytes > 1100 || !l.pending_frames || l.pending_frames > 4096 ||
        l.pending_bytes < l.payload_bytes || l.pending_bytes > 64 * 1024 * 1024 ||
        l.bytes_per_second < datagram_limit || l.bytes_per_second > 64 * 1024 * 1024 ||
        l.packets_per_second < 4 || l.packets_per_second > 1000000 ||
        !l.packets_per_tick || l.packets_per_tick > 4096 ||
        l.tick_interval < 1ms || l.tick_interval > 100ms ||
        l.retry_interval < l.tick_interval || l.retry_interval > 5s ||
        l.heartbeat_interval < l.tick_interval || l.heartbeat_interval > 10s ||
        l.idle_timeout < l.heartbeat_interval * 3 || l.idle_timeout > 24h ||
        l.handshake_timeout < l.retry_interval * 2 || l.handshake_timeout > 60s ||
        l.maximum_frame_age < l.tick_interval || l.maximum_frame_age > l.idle_timeout)
        return fail(ErrorCode::invalid_argument, "Invalid realtime resource, rate or lifetime limits");
    return {};
}
struct Envelope
{
    Kind kind;
    SessionId id;
    std::uint64_t sequence;
    std::string_view header, ciphertext;
};
std::optional<Envelope> unpack(std::string_view bytes, bool server)
{
    if (bytes.size() < header_size + 29 || bytes.size() > datagram_limit || bytes.substr(0, 5) != "IIRT\1" ||
        detail::byte(bytes, 5) < 1 || detail::byte(bytes, 5) > 6 ||
        detail::byte(bytes, 6) != unsigned(server) || bytes[7] != 0) return {};
    Envelope result{static_cast<Kind>(bytes[5]), {}, 0, bytes.substr(0, header_size), bytes.substr(header_size)};
    std::copy_n(bytes.begin() + 8, 16, result.id.bytes.begin());
    auto sequence = bytes.substr(24, 8); wire::take_be(sequence, result.sequence, 8);
    if (nil(result.id) || !result.sequence || result.sequence >= packet_limit) return {};
    return result;
}
struct ReplayWindow
{
    std::uint64_t newest = 0, bits = 0;
    bool contains(std::uint64_t sequence) const
    {
        if (sequence > newest) return false;
        const auto gap = newest - sequence;
        return gap >= 64 || (bits & (1ULL << gap));
    }
    void accept(std::uint64_t sequence, RealtimeStatistics& statistics)
    {
        if (sequence > newest)
        {
            const auto gap = sequence - newest;
            if (newest && gap > 1) statistics.sequence_gaps += gap - 1;
            bits = gap >= 64 ? 1 : (bits << gap) | 1; newest = sequence;
        }
        else bits |= 1ULL << (newest - sequence);
    }
};
struct Bucket
{
    double bytes = 0, packets = 0; Clock::time_point updated{};
    void reset(Clock::time_point now) { bytes = 2 * datagram_limit; packets = 4; updated = now; }
    bool take(std::size_t count, double rate, double packet_rate, double burst, Clock::time_point now)
    {
        const auto seconds = std::max(0.0, std::chrono::duration<double>(now - updated).count()); updated = now;
        bytes = std::min(std::max<double>(datagram_limit, burst), bytes + rate * seconds);
        packets = std::min(std::max(4.0, packet_rate / 4), packets + packet_rate * seconds);
        if (bytes < count || packets < 1) return false;
        bytes -= count; packets -= 1; return true;
    }
};
using Stream = std::pair<RealtimePeerId, std::uint16_t>;
struct Pending
{
    Stream stream; std::uint64_t sequence;
    std::shared_ptr<const std::string> bytes; Clock::time_point updated;
};
struct Latest { std::uint64_t sequence, packet; };
struct Link
{
    SessionId id, nonce;
    RealtimePeerInfo info;
    std::shared_ptr<PayloadCipher> cipher;
    std::size_t channels = 0, payload_bytes = 0;
    bool ready = false, feedback_missing = false;
    Clock::time_point expires{}, last_receive{}, last_join{}, last_ping{}, feedback{}, decay{};
    std::string join, welcome;
    std::uint64_t sent_sequence = 0, last_feedback_ack = 0, last_loss_examined = 0;
    std::map<std::uint64_t, Clock::time_point> pings;
    ReplayWindow replay;
    std::list<Pending> pending;
    std::map<Stream, std::list<Pending>::iterator> pending_index;
    std::map<Stream, Latest> latest;
    std::size_t pending_bytes = 0;
    Bucket tx, rx, control, rx_control;
    double congestion_window = 2 * datagram_limit, smoothed_rtt = 0.1;
    std::chrono::microseconds rtt{0};
    void initialize(Clock::time_point now)
    { last_receive = last_ping = feedback = decay = now; tx.reset(now); rx.reset(now); control.reset(now); rx_control.reset(now); }
    double rate(const RealtimeLimits& limits) const
    { return feedback_missing ? datagram_limit : std::min<double>(limits.bytes_per_second, std::max<double>(datagram_limit, congestion_window / smoothed_rtt)); }
};
Result<std::string> pack(Link& link, Kind kind, bool server, std::string_view body)
{
    if (link.sent_sequence + 1 >= packet_limit)
        return fail(ErrorCode::expired, "Realtime key packet limit reached; obtain a fresh ticket");
    std::string header("IIRT\1", 5); header += static_cast<char>(kind); header += char(server); header += '\0';
    header.append(reinterpret_cast<const char*>(link.id.bytes.data()), 16);
    wire::append_be(header, ++link.sent_sequence, 8);
    auto sealed = link.cipher->seal(body, header); if (!sealed) return std::unexpected(sealed.error());
    if (header.size() + sealed->size() > datagram_limit) return fail(ErrorCode::too_large, "Realtime datagram exceeds wire limit");
    return header + *sealed;
}
double control_packet_rate(const RealtimeLimits& limits)
{ return std::clamp(4.0 / std::chrono::duration<double>(limits.heartbeat_interval).count(), 16.0, 2000.0); }
bool transmit(Udp& socket, Link& link, std::string_view bytes, bool control,
              const RealtimeLimits& limits, RealtimeStatistics& statistics, Clock::time_point now)
{
    // Reserve a small, independently bounded liveness budget; data pacing
    // cannot prevent heartbeat/close traffic from progressing.
    const auto control_packets = control_packet_rate(limits);
    bool admitted = control ? link.control.take(bytes.size(), std::max(4800.0, 120 * control_packets), control_packets, datagram_limit, now) :
        link.tx.take(bytes.size(), link.rate(limits), limits.packets_per_second, link.congestion_window, now);
    if (!admitted) return false;
    if (!socket.send(bytes, link.info.endpoint)) return false;
    ++statistics.sent_packets; statistics.sent_bytes += bytes.size(); return true;
}
bool control(Udp& socket, Link& link, Kind kind, bool server, std::string_view body,
             const RealtimeLimits& limits, RealtimeStatistics& statistics, Clock::time_point now)
{
    auto bytes = pack(link, kind, server, body);
    return bytes && transmit(socket, link, *bytes, true, limits, statistics, now);
}
Result<void> enqueue(Link& link, Stream stream, std::uint64_t sequence, std::shared_ptr<const std::string> bytes,
                     const RealtimeLimits& limits, RealtimeStatistics& statistics, Clock::time_point now)
{
    if (stream.second >= link.channels) return fail(ErrorCode::invalid_argument, "Realtime channel was not negotiated");
    if (bytes->size() > link.payload_bytes) return fail(ErrorCode::too_large, "Realtime payload exceeds negotiated limit");
    const auto found = link.pending_index.find(stream);
    const auto old_size = found == link.pending_index.end() ? 0 : found->second->bytes->size();
    if ((found == link.pending_index.end() && link.pending.size() >= limits.pending_frames) ||
        bytes->size() > limits.pending_bytes - (link.pending_bytes - old_size))
    { ++statistics.backpressure; return fail(ErrorCode::would_block, "Realtime latest-value queue is full"); }
    link.pending_bytes = link.pending_bytes - old_size + bytes->size();
    if (found != link.pending_index.end())
    {
        auto& pending = *found->second; pending.sequence = sequence; pending.bytes = std::move(bytes); pending.updated = now;
        ++statistics.coalesced_frames;
    }
    else
    {
        link.pending.push_back({stream, sequence, std::move(bytes), now});
        link.pending_index.emplace(stream, std::prev(link.pending.end()));
    }
    return {};
}
void pop(Link& link)
{
    link.pending_bytes -= link.pending.front().bytes->size();
    link.pending_index.erase(link.pending.front().stream); link.pending.pop_front();
}
void flush(Udp& socket, Link& link, bool server, const RealtimeLimits& limits, RealtimeStatistics& statistics,
           Clock::time_point now, std::size_t& budget)
{
    unsigned served = 0;
    while (!link.pending.empty() && budget && served < 4)
    {
        const auto& pending = link.pending.front();
        if (now - pending.updated >= limits.maximum_frame_age) { pop(link); ++statistics.expired_frames; continue; }
        const auto wire_size = header_size + 29 + 18 + pending.bytes->size();
        // Do not allocate/encrypt a fresh packet until pacing admits a send.
        if (!link.tx.take(wire_size, link.rate(limits), link.feedback_missing ? 1.0 : limits.packets_per_second, link.congestion_window, now)) break;
        std::string body; wire::append_be(body, pending.stream.first, 8); wire::append_be(body, pending.stream.second, 2);
        wire::append_be(body, pending.sequence, 8); body += *pending.bytes;
        auto bytes = pack(link, Kind::data, server, body);
        if (!bytes || !socket.send(*bytes, link.info.endpoint)) break;
        ++statistics.sent_packets; statistics.sent_bytes += bytes->size(); ++statistics.sent_frames;
        --budget; ++served; pop(link);
    }
}
std::string feedback_body(const Link& link, std::uint64_t id)
{
    std::string bytes; wire::append_be(bytes, id, 8); wire::append_be(bytes, link.replay.newest, 8);
    wire::append_be(bytes, link.replay.bits, 8); return bytes;
}
void feedback(Link& link, std::string_view body, bool pong, const RealtimeLimits& limits,
              RealtimeStatistics& statistics, Clock::time_point now)
{
    std::uint64_t id = 0, newest = 0, bits = 0;
    wire::take_be(body, id, 8); wire::take_be(body, newest, 8); wire::take_be(body, bits, 8);
    auto pending_ping = link.pings.find(id);
    if (pong && pending_ping != link.pings.end())
    {
        link.rtt = std::chrono::duration_cast<std::chrono::microseconds>(now - pending_ping->second);
        const auto measured = std::clamp(std::chrono::duration<double>(link.rtt).count(), 0.001, 10.0);
        link.smoothed_rtt = link.smoothed_rtt * 0.875 + measured * 0.125;
        link.pings.erase(pending_ping);
    }
    if (!newest || newest > link.sent_sequence || !(bits & 1)) return;
    if (newest <= link.last_feedback_ack) return;
    link.feedback = now; link.feedback_missing = false;
    bool loss = false;
    // Leave the three newest packets unclassified to tolerate short reorder.
    for (std::uint64_t gap = 3; gap < 64 && gap < newest; ++gap)
        if (newest - gap > link.last_loss_examined && !(bits & (1ULL << gap))) { loss = true; break; }
    if (loss) { link.congestion_window = std::max(1.0, link.congestion_window / 2); ++statistics.congestion_events; }
    else link.congestion_window = std::min<double>(65536, link.congestion_window + datagram_limit);
    link.last_feedback_ack = newest;
    link.last_loss_examined = newest > 3 ? newest - 3 : 0;
    link.tx.bytes = std::min(link.tx.bytes, link.congestion_window);
    (void)limits;
}
void heartbeat(Udp& socket, Link& link, bool server, const RealtimeLimits& limits,
               RealtimeStatistics& statistics, Clock::time_point now)
{
    if (now - link.feedback > std::max(limits.heartbeat_interval * 3, 300ms) &&
        now - link.decay >= limits.heartbeat_interval)
    {
        link.congestion_window = std::max(120.0, link.congestion_window / 2);
        link.feedback_missing = true; link.tx.packets = std::min(link.tx.packets, 1.0);
        link.decay = now; ++statistics.congestion_events;
    }
    if (now - link.last_ping < limits.heartbeat_interval) return;
    const auto id = link.sent_sequence + 1;
    if (control(socket, link, Kind::ping, server, feedback_body(link, id), limits, statistics, now))
    {
        link.last_ping = now;
        if (link.pings.size() == 64) link.pings.erase(link.pings.begin());
        link.pings.emplace(id, now);
    }
}
struct Data { RealtimePeerId origin; std::uint16_t channel; std::uint64_t sequence; std::string_view bytes; };
std::optional<Data> data(std::string_view body, const Link& link, bool server)
{
    if (body.size() < 18 || body.size() - 18 > link.payload_bytes) return {};
    std::uint64_t origin = 0, channel = 0, sequence = 0;
    wire::take_be(body, origin, 8); wire::take_be(body, channel, 2); wire::take_be(body, sequence, 8);
    if (channel >= link.channels || !sequence || (server && origin != 0)) return {};
    return Data{origin, static_cast<std::uint16_t>(channel), sequence, body};
}
bool latest(Link& link, const Data& frame, std::uint64_t packet, const RealtimeLimits& limits, RealtimeStatistics& statistics)
{
    const Stream key{frame.origin, frame.channel}; auto found = link.latest.find(key);
    if (found != link.latest.end() && frame.sequence <= found->second.sequence) { ++statistics.stale_frames; return false; }
    const auto capacity = std::max<std::size_t>(64, limits.pending_frames);
    if (found == link.latest.end() && link.latest.size() >= capacity)
    {
        auto oldest = std::min_element(link.latest.begin(), link.latest.end(), [](const auto& a, const auto& b) { return a.second.packet < b.second.packet; });
        link.latest.erase(oldest);
    }
    link.latest[key] = {frame.sequence, packet}; return true;
}
Error remote_reason(std::string_view body)
{
    if (static_cast<Reason>(body[0]) == Reason::revoked) return make_error(ErrorCode::permission_denied, "Realtime membership was revoked");
    if (static_cast<Reason>(body[0]) == Reason::expired) return make_error(ErrorCode::expired, "Realtime session expired");
    return make_error(ErrorCode::closed, "Realtime remote endpoint closed");
}
bool body_valid(Kind kind, std::string_view body, const Link& link, bool server)
{
    if (kind == Kind::data) return data(body, link, server).has_value();
    if (kind == Kind::ping || kind == Kind::pong) return body.size() == 24;
    if (kind == Kind::bye) return body.size() == 1 && detail::byte(body, 0) <= 2;
    return false;
}
bool accept(Link& link, const Envelope& envelope, std::string_view body, bool server,
            const RealtimeLimits& limits, RealtimeStatistics& statistics, Clock::time_point now)
{
    // Authenticate and validate before committing any replay/activity state.
    if (!body_valid(envelope.kind, body, link, server) || link.replay.contains(envelope.sequence))
    { ++statistics.rejected_packets; return false; }
    if (envelope.kind == Kind::ping || envelope.kind == Kind::pong)
    {
        auto fields = body; std::uint64_t id = 0, newest = 0, bits = 0;
        wire::take_be(fields, id, 8); wire::take_be(fields, newest, 8); wire::take_be(fields, bits, 8);
        if (!id || (envelope.kind == Kind::ping && id != envelope.sequence) ||
            (envelope.kind == Kind::pong && id > link.sent_sequence) || newest > link.sent_sequence ||
            (!newest && bits) || (newest && !(bits & 1)) || (newest < 64 && (bits >> newest)))
        { ++statistics.rejected_packets; return false; }
    }
    const auto size = envelope.header.size() + envelope.ciphertext.size();
    const auto control_rate = control_packet_rate(limits);
    const bool admitted = envelope.kind == Kind::data ?
        link.rx.take(size, limits.bytes_per_second, limits.packets_per_second, std::max<std::size_t>(2400, limits.bytes_per_second / 4), now) :
        link.rx_control.take(size, std::max(4800.0, 120 * control_rate), control_rate, datagram_limit, now);
    if (!admitted)
    { ++statistics.rejected_packets; return false; }
    link.replay.accept(envelope.sequence, statistics); link.last_receive = now; return true;
}
} // namespace

struct RealtimeServer::Impl : std::enable_shared_from_this<RealtimeServer::Impl>
{
    runtime::EventLoop& loop; Udp socket; runtime::TaskToken timer;
    RealtimeServer* owner; bool active = false; std::uint64_t generation = 0, next_peer = 0;
    RealtimeLimits limits; RealtimeStatistics totals;
    std::map<SessionId, std::shared_ptr<Link>> links;
    std::map<RealtimePeerId, SessionId> identifiers;
    std::vector<std::uint64_t> values;
    std::size_t cursor = 0;
    Impl(runtime::EventLoop& event_loop, RealtimeServer* parent) : loop(event_loop), socket(event_loop), owner(parent) {}
    std::shared_ptr<Link> find(RealtimePeerId peer) const
    {
        auto id = identifiers.find(peer); if (id == identifiers.end()) return {};
        auto link = links.find(id->second); return link == links.end() ? nullptr : link->second;
    }
    bool current(const std::shared_ptr<Link>& link) const
    { auto found = links.find(link->id); return active && found != links.end() && found->second == link; }
    void drop(std::shared_ptr<Link> link, Error reason, Reason wire_reason, bool notify = true)
    {
        if (!current(link)) return;
        if (link->ready) control(socket, *link, Kind::bye, true, std::string(1, char(wire_reason)), limits, totals, Clock::now());
        identifiers.erase(link->info.peer); links.erase(link->id);
        if (notify && owner && link->ready)
        {
            auto callback = owner->disconnected;
            if (callback) { try { callback(link->info, std::move(reason)); } catch (...) {} }
        }
    }
    void close(bool notify)
    {
        if (!active && links.empty()) return;
        std::vector<RealtimePeerInfo> closed; const auto epoch = ++generation;
        for (auto& [id, link] : links)
        {
            if (link->ready)
            {
                control(socket, *link, Kind::bye, true, std::string(1, char(Reason::closed)), limits, totals, Clock::now());
                closed.push_back(link->info);
            }
        }
        active = false; timer.cancel(); socket.received = {}; socket.failed = {}; socket.close(); links.clear(); identifiers.clear();
        if (notify)
            for (auto& info : closed)
            {
                if (!owner || generation != epoch) break;
                auto callback = owner->disconnected;
                if (callback) { try { callback(info, make_error(ErrorCode::closed, "Realtime server closed")); } catch (...) {} }
            }
    }
    void join(std::shared_ptr<Link> link, const Envelope& envelope, std::string_view body, IpEndpoint remote, Clock::time_point now)
    {
        if (body.size() != 20 || envelope.sequence != 1) { ++totals.rejected_packets; return; }
        SessionId nonce; std::copy_n(body.begin(), 16, nonce.bytes.begin());
        auto fields = body.substr(16); std::uint64_t channels = 0, payload = 0;
        wire::take_be(fields, channels, 2); wire::take_be(fields, payload, 2);
        if (nil(nonce) || !channels || channels > 256 || !payload || payload > 1100) { ++totals.rejected_packets; return; }
        if (link->ready)
        {
            if (remote != link->info.endpoint || nonce != link->nonce || body != link->join)
            { ++totals.rejected_packets; return; }
            // A duplicate join can recover a lost welcome, but cannot extend
            // the session's authenticated liveness deadline.
            if (now - link->last_join >= limits.retry_interval)
            { transmit(socket, *link, link->welcome, true, limits, totals, now); link->last_join = now; }
            return;
        }
        if (now >= link->expires) { drop(link, make_error(ErrorCode::expired, "Realtime ticket expired"), Reason::expired, false); return; }
        link->nonce = nonce; link->join = body; link->info.endpoint = remote;
        link->channels = std::min<std::size_t>(channels, limits.channels);
        link->payload_bytes = std::min<std::size_t>(payload, limits.payload_bytes);
        link->initialize(now); link->last_join = now; link->replay.accept(envelope.sequence, totals);
        std::string welcome(reinterpret_cast<const char*>(nonce.bytes.data()), 16);
        wire::append_be(welcome, link->info.peer, 8); wire::append_be(welcome, link->channels, 2);
        wire::append_be(welcome, link->payload_bytes, 2); wire::append_be(welcome, link->info.room.size(), 2); welcome += link->info.room;
        auto bytes = pack(*link, Kind::welcome, true, welcome);
        if (!bytes) { drop(link, bytes.error(), Reason::closed, false); return; }
        link->welcome = std::move(*bytes); link->ready = true;
        transmit(socket, *link, link->welcome, true, limits, totals, now);
        if (owner)
        {
            auto callback = owner->connected;
            if (callback) { try { callback(link->info); } catch (...) { drop(link, make_error(ErrorCode::remote_error, "Realtime handler failed"), Reason::closed); } }
        }
    }
    void receive(Datagram packet)
    {
        if (!active) return;
        ++totals.received_packets; totals.received_bytes += packet.bytes.size();
        const auto envelope = unpack(packet.bytes, false);
        if (!envelope) { ++totals.rejected_packets; return; }
        auto found = links.find(envelope->id);
        if (found == links.end()) { ++totals.rejected_packets; return; }
        auto link = found->second; const auto now = Clock::now();
        if (link->ready && packet.sender != link->info.endpoint) { ++totals.rejected_packets; return; }
        if (link->ready && now - link->last_receive >= limits.idle_timeout)
        { ++totals.rejected_packets; drop(link, make_error(ErrorCode::expired, "Realtime session expired"), Reason::expired); return; }
        auto plaintext = link->cipher->open(envelope->ciphertext, envelope->header);
        if (!plaintext) { ++totals.rejected_packets; return; }
        if (envelope->kind == Kind::join) { join(link, *envelope, *plaintext, packet.sender, now); return; }
        if (!link->ready || now - link->last_receive >= limits.idle_timeout)
        { ++totals.rejected_packets; return; }
        if (!accept(*link, *envelope, *plaintext, true, limits, totals, now)) return;
        if (envelope->kind == Kind::bye)
        { drop(link, remote_reason(*plaintext), Reason::closed); return; }
        if (envelope->kind == Kind::ping || envelope->kind == Kind::pong)
        {
            feedback(*link, *plaintext, envelope->kind == Kind::pong, limits, totals, now);
            if (envelope->kind == Kind::ping)
            {
                auto body = std::string_view(*plaintext); std::uint64_t id = 0; wire::take_be(body, id, 8);
                control(socket, *link, Kind::pong, true, feedback_body(*link, id), limits, totals, now);
            }
            return;
        }
        auto frame = *data(*plaintext, *link, true);
        if (!latest(*link, frame, envelope->sequence, limits, totals)) return;
        ++totals.received_frames;
        if (owner)
        {
            RealtimeFrame value{link->info.peer, link->info.room, frame.channel, frame.sequence, std::string(frame.bytes)};
            auto callback = owner->received;
            if (callback) { try { callback(std::move(value)); } catch (...) { drop(link, make_error(ErrorCode::remote_error, "Realtime handler failed"), Reason::closed); } }
        }
    }
    void tick()
    {
        if (!active) return;
        const auto now = Clock::now(); const auto epoch = generation;
        std::vector<std::shared_ptr<Link>> snapshot; for (auto& [id, link] : links) snapshot.push_back(link);
        for (auto& link : snapshot)
        {
            if (!owner || !active || generation != epoch) return;
            if (!current(link)) continue;
            if ((!link->ready && now >= link->expires) || (link->ready && now - link->last_receive >= limits.idle_timeout))
            { drop(link, make_error(ErrorCode::expired, "Realtime session expired"), Reason::expired); continue; }
            if (link->ready && link->sent_sequence + 1 >= packet_limit)
            { drop(link, make_error(ErrorCode::expired, "Realtime key packet limit reached"), Reason::expired); continue; }
            if (link->ready) heartbeat(socket, *link, true, limits, totals, now);
        }
        if (!active || generation != epoch || snapshot.empty()) return;
        std::size_t budget = limits.packets_per_tick;
        const auto start = cursor % snapshot.size(); std::size_t visited = 0;
        for (; visited < snapshot.size() && budget; ++visited)
        {
            auto& link = snapshot[(start + visited) % snapshot.size()];
            if (current(link) && link->ready) flush(socket, *link, true, limits, totals, now, budget);
        }
        cursor = (start + std::max<std::size_t>(visited, 1)) % snapshot.size();
    }
    Result<std::uint64_t> next(std::uint16_t channel)
    {
        if (!active) return fail(ErrorCode::closed, "Realtime server is closed");
        if (channel >= limits.channels) return fail(ErrorCode::invalid_argument, "Invalid realtime channel");
        if (values[channel] == std::numeric_limits<std::uint64_t>::max()) return fail(ErrorCode::expired, "Realtime value sequence exhausted");
        return ++values[channel];
    }
    Result<std::size_t> fanout(std::string_view room, Stream stream, std::uint64_t sequence,
                              std::shared_ptr<const std::string> bytes, RealtimePeerId except)
    {
        std::size_t count = 0; const auto now = Clock::now();
        for (auto& [id, link] : links)
            if (link->ready && link->info.room == room && link->info.peer != except)
                if (enqueue(*link, stream, sequence, bytes, limits, totals, now)) ++count;
        return count;
    }
};

RealtimeServer::RealtimeServer(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop, this)) {}
RealtimeServer::~RealtimeServer() { p_->owner = nullptr; p_->close(false); }
Result<void> RealtimeServer::listen(IpEndpoint endpoint, RealtimeLimits limits)
{
    auto p = p_; if (p->active) return fail(ErrorCode::invalid_state, "Realtime server is already listening");
    auto valid = validate(limits); if (!valid) return valid;
    UdpOptions options; options.maximum_datagram_bytes = datagram_limit;
    auto bound = p->socket.bind(endpoint, options); if (!bound) return bound;
    p->limits = limits; p->totals = {}; p->values.assign(limits.channels, 0); p->cursor = 0; ++p->generation; p->active = true;
    p->socket.received = [weak = std::weak_ptr<Impl>(p)](Datagram packet) { if (auto keep = weak.lock()) keep->receive(std::move(packet)); };
    p->socket.failed = [weak = std::weak_ptr<Impl>(p)](auto) { if (auto keep = weak.lock()) ++keep->totals.rejected_packets; };
    p->timer = p->loop.every(limits.tick_interval, [weak = std::weak_ptr<Impl>(p)] { if (auto keep = weak.lock()) keep->tick(); }).token;
    if (!p->timer.pending()) { p->close(false); return fail(ErrorCode::unavailable, "Core realtime dispatch admission failed"); }
    return {};
}
Result<RealtimeTicket> RealtimeServer::issue(std::string room, std::chrono::milliseconds lifetime)
{
    auto p = p_; if (!p->active) return fail(ErrorCode::closed, "Realtime server is closed");
    if (!room_valid(room) || lifetime <= 0ms || lifetime > 5min) return fail(ErrorCode::invalid_argument, "Invalid realtime room or ticket lifetime");
    if (p->links.size() >= p->limits.peers) return fail(ErrorCode::would_block, "Realtime participant capacity reached");
    if (p->next_peer == std::numeric_limits<RealtimePeerId>::max()) return fail(ErrorCode::expired, "Realtime peer identifiers exhausted");
    auto id = SessionId::generate(); if (!id) return std::unexpected(id.error());
    if (p->links.contains(*id)) return fail(ErrorCode::unavailable, "Realtime credential identifier collision");
    auto key = Aes256Gcm::generate_key(); if (!key) return std::unexpected(key.error());
    RealtimeTicket ticket{*id, ++p->next_peer, std::move(room), *key};
    auto link = std::make_shared<Link>(); link->id = *id; link->info.peer = ticket.peer; link->info.room = ticket.room;
    link->cipher = std::make_shared<Aes256Gcm>(*key); link->expires = Clock::now() + lifetime;
    p->links.emplace(*id, link); p->identifiers.emplace(ticket.peer, *id); return ticket;
}
Result<std::uint64_t> RealtimeServer::send(RealtimePeerId peer, std::uint16_t channel, std::string bytes)
{
    auto p = p_; if (!p->active) return fail(ErrorCode::closed, "Realtime server is closed"); auto link = p->find(peer);
    if (!link || !link->ready) return fail(ErrorCode::not_found, "Realtime participant is not connected");
    auto sequence = p->next(channel); if (!sequence) return std::unexpected(sequence.error());
    auto queued = enqueue(*link, {0, channel}, *sequence, std::make_shared<const std::string>(std::move(bytes)), p->limits, p->totals, Clock::now());
    if (!queued) return std::unexpected(queued.error()); return *sequence;
}
Result<std::size_t> RealtimeServer::broadcast(std::string_view room, std::uint16_t channel, std::string bytes, RealtimePeerId except)
{
    auto p = p_;
    if (!room_valid(room)) return fail(ErrorCode::invalid_argument, "Invalid realtime room");
    if (bytes.size() > p->limits.payload_bytes) return fail(ErrorCode::too_large, "Realtime publication exceeds server limit");
    auto sequence = p->next(channel); if (!sequence) return std::unexpected(sequence.error());
    return p->fanout(room, {0, channel}, *sequence, std::make_shared<const std::string>(std::move(bytes)), except);
}
Result<std::size_t> RealtimeServer::relay(const RealtimeFrame& frame)
{
    auto p = p_; if (!p->active) return fail(ErrorCode::closed, "Realtime server is closed"); auto link = p->find(frame.peer);
    if (!link || !link->ready || link->info.room != frame.room) return fail(ErrorCode::permission_denied, "Realtime relay source is not an active room member");
    auto latest = link->latest.find({0, frame.channel});
    if (latest == link->latest.end() || latest->second.sequence != frame.sequence) return fail(ErrorCode::replay, "Realtime relay source frame is obsolete");
    if (frame.bytes.size() > link->payload_bytes) return fail(ErrorCode::too_large, "Realtime relay payload exceeds negotiated limit");
    return p->fanout(frame.room, {frame.peer, frame.channel}, frame.sequence, std::make_shared<const std::string>(frame.bytes), frame.peer);
}
bool RealtimeServer::revoke(RealtimePeerId peer)
{
    auto p = p_; auto link = p->find(peer); if (!link) return false;
    p->drop(link, make_error(ErrorCode::permission_denied, "Realtime membership was revoked"), Reason::revoked); return true;
}
void RealtimeServer::close() { auto p = p_; p->close(true); }
bool RealtimeServer::listening() const { return p_->active; }
std::uint16_t RealtimeServer::port() const { return p_->socket.port(); }
std::vector<RealtimePeerInfo> RealtimeServer::peers() const
{
    std::vector<RealtimePeerInfo> result;
    for (auto& [id, link] : p_->links) if (link->ready) { auto info = link->info; info.round_trip_time = link->rtt; result.push_back(std::move(info)); }
    return result;
}
std::size_t RealtimeServer::pending_tickets() const
{ return std::count_if(p_->links.begin(), p_->links.end(), [](const auto& pair) { return !pair.second->ready; }); }
std::size_t RealtimeServer::pending_bytes() const
{ std::size_t count = 0; for (auto& [id, link] : p_->links) count += link->pending_bytes; return count; }
RealtimeStatistics RealtimeServer::statistics() const
{
    auto result = p_->totals;
    for (auto& [id, link] : p_->links) if (link->ready)
    {
        result.round_trip_time = std::max(result.round_trip_time, link->rtt);
        const auto rate = static_cast<std::size_t>(link->rate(p_->limits));
        result.send_rate_bytes_per_second += std::min(rate, std::numeric_limits<std::size_t>::max() - result.send_rate_bytes_per_second);
    }
    return result;
}

struct RealtimeClient::Impl : std::enable_shared_from_this<RealtimeClient::Impl>
{
    runtime::EventLoop& loop; Udp socket; runtime::TaskToken timer; RealtimeClient* owner;
    RealtimeState state = RealtimeState::closed; std::uint64_t generation = 0;
    std::shared_ptr<Link> link; RealtimeLimits limits; RealtimeStatistics totals;
    std::optional<Error> failure; Clock::time_point started{}; std::vector<std::uint64_t> values;
    Impl(runtime::EventLoop& event_loop, RealtimeClient* parent) : loop(event_loop), socket(event_loop), owner(parent) {}
    void stop(std::optional<Error> reason, bool notify, bool send_bye)
    {
        const bool was_active = state == RealtimeState::connecting || state == RealtimeState::ready;
        if (!was_active) return;
        const auto epoch = ++generation;
        if (send_bye && link && link->ready)
            control(socket, *link, Kind::bye, false, std::string(1, char(Reason::closed)), limits, totals, Clock::now());
        state = reason ? RealtimeState::failed : RealtimeState::closed; failure = reason;
        timer.cancel(); socket.received = {}; socket.failed = {}; socket.close();
        if (link) { link->pending.clear(); link->pending_index.clear(); link->pending_bytes = 0; link->pings.clear(); link->latest.clear(); link->cipher.reset(); }
        if (!notify || !owner) return;
        if (reason)
        {
            auto callback = owner->failed;
            if (callback) { try { callback(*reason); } catch (...) {} }
        }
        if (owner && generation == epoch)
        {
            auto callback = owner->disconnected;
            if (callback) { try { callback(); } catch (...) {} }
        }
    }
    void welcome(const Envelope& envelope, std::string_view body, Clock::time_point now)
    {
        if (state != RealtimeState::connecting || envelope.sequence != 1 || body.size() < 30 || body.size() > 158) { ++totals.rejected_packets; return; }
        SessionId nonce; std::copy_n(body.begin(), 16, nonce.bytes.begin()); body.remove_prefix(16);
        std::uint64_t peer = 0, channels = 0, payload = 0, length = 0;
        wire::take_be(body, peer, 8); wire::take_be(body, channels, 2); wire::take_be(body, payload, 2); wire::take_be(body, length, 2);
        if (nonce != link->nonce || peer != link->info.peer || length != body.size() || body != link->info.room ||
            !channels || channels > limits.channels || !payload || payload > limits.payload_bytes)
        { ++totals.rejected_packets; return; }
        link->channels = channels; link->payload_bytes = payload; link->ready = true; link->last_receive = link->feedback = now;
        link->replay.accept(envelope.sequence, totals); state = RealtimeState::ready;
        if (owner)
        {
            const auto epoch = generation; auto callback = owner->connected;
            if (callback) { try { callback(); } catch (...) { if (generation == epoch) stop(make_error(ErrorCode::remote_error, "Realtime handler failed"), true, true); } }
        }
    }
    void receive(Datagram packet)
    {
        if (state != RealtimeState::connecting && state != RealtimeState::ready) return;
        ++totals.received_packets; totals.received_bytes += packet.bytes.size();
        auto envelope = unpack(packet.bytes, true); auto current = link;
        if (!envelope || envelope->id != current->id || packet.sender != current->info.endpoint) { ++totals.rejected_packets; return; }
        const auto now = Clock::now();
        if ((state == RealtimeState::connecting && now - started >= limits.handshake_timeout) ||
            (state == RealtimeState::ready && now - current->last_receive >= limits.idle_timeout))
        { stop(make_error(ErrorCode::expired, "Realtime session deadline elapsed"), true, false); return; }
        auto plaintext = current->cipher->open(envelope->ciphertext, envelope->header);
        if (!plaintext) { ++totals.rejected_packets; return; }
        if (envelope->kind == Kind::welcome) { welcome(*envelope, *plaintext, now); return; }
        if (state != RealtimeState::ready || !accept(*current, *envelope, *plaintext, false, limits, totals, now)) return;
        if (envelope->kind == Kind::bye) { stop(remote_reason(*plaintext), true, false); return; }
        if (envelope->kind == Kind::ping || envelope->kind == Kind::pong)
        {
            feedback(*current, *plaintext, envelope->kind == Kind::pong, limits, totals, now);
            if (envelope->kind == Kind::ping)
            {
                auto body = std::string_view(*plaintext); std::uint64_t id = 0; wire::take_be(body, id, 8);
                control(socket, *current, Kind::pong, false, feedback_body(*current, id), limits, totals, now);
            }
            return;
        }
        const auto frame = *data(*plaintext, *current, false);
        if (!latest(*current, frame, envelope->sequence, limits, totals)) return;
        ++totals.received_frames;
        if (owner)
        {
            RealtimeFrame value{frame.origin, current->info.room, frame.channel, frame.sequence, std::string(frame.bytes)};
            const auto epoch = generation; auto callback = owner->received;
            if (callback) { try { callback(std::move(value)); } catch (...) { if (generation == epoch) stop(make_error(ErrorCode::remote_error, "Realtime handler failed"), true, true); } }
        }
    }
    void tick()
    {
        const auto now = Clock::now(); auto current = link;
        if (state == RealtimeState::connecting)
        {
            if (now - started >= limits.handshake_timeout) { stop(make_error(ErrorCode::expired, "Realtime handshake deadline elapsed"), true, false); return; }
            if (now - current->last_join >= limits.retry_interval)
            { transmit(socket, *current, current->join, true, limits, totals, now); current->last_join = now; }
            return;
        }
        if (state != RealtimeState::ready) return;
        if (now - current->last_receive >= limits.idle_timeout || current->sent_sequence + 1 >= packet_limit)
        { stop(make_error(ErrorCode::expired, "Realtime session or key lifetime elapsed"), true, true); return; }
        heartbeat(socket, *current, false, limits, totals, now);
        std::size_t budget = limits.packets_per_tick; flush(socket, *current, false, limits, totals, now, budget);
    }
};

RealtimeClient::RealtimeClient(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop, this)) {}
RealtimeClient::~RealtimeClient() { p_->owner = nullptr; p_->stop({}, false, true); }
Result<void> RealtimeClient::connect(IpEndpoint server, const RealtimeTicket& ticket, RealtimeLimits limits)
{
    auto p = p_;
    if (p->state == RealtimeState::connecting || p->state == RealtimeState::ready) return fail(ErrorCode::invalid_state, "Realtime client already has an active session");
    auto valid = validate(limits); if (!valid) return valid;
    if (!endpoint_valid(server) || nil(ticket.id) || !ticket.peer || !room_valid(ticket.room) ||
        std::all_of(ticket.key.begin(), ticket.key.end(), [](auto b) { return b == 0; }))
        return fail(ErrorCode::invalid_argument, "Invalid realtime server endpoint or credential");
    auto nonce = SessionId::generate(); if (!nonce) return std::unexpected(nonce.error());
    auto link = std::make_shared<Link>(); link->id = ticket.id; link->nonce = *nonce;
    link->info = {ticket.peer, ticket.room, server}; link->cipher = std::make_shared<Aes256Gcm>(ticket.key);
    link->channels = limits.channels; link->payload_bytes = limits.payload_bytes;
    const auto now = Clock::now(); link->initialize(now); link->last_join = now;
    std::string join(reinterpret_cast<const char*>(nonce->bytes.data()), 16);
    wire::append_be(join, limits.channels, 2); wire::append_be(join, limits.payload_bytes, 2);
    auto bytes = pack(*link, Kind::join, false, join); if (!bytes) return std::unexpected(bytes.error()); link->join = std::move(*bytes);
    UdpOptions options; options.maximum_datagram_bytes = datagram_limit;
    auto bound = p->socket.bind({IpAddress::any(server.address.family()), 0}, options); if (!bound) return bound;
    auto connected = p->socket.connect_peer(server); if (!connected) { p->socket.close(); return connected; }
    p->limits = limits; p->totals = {}; p->failure.reset(); p->link = link; p->values.assign(limits.channels, 0);
    p->started = now; ++p->generation; p->state = RealtimeState::connecting;
    p->socket.received = [weak = std::weak_ptr<Impl>(p)](Datagram packet) { if (auto keep = weak.lock()) keep->receive(std::move(packet)); };
    p->socket.failed = [weak = std::weak_ptr<Impl>(p)](auto) { if (auto keep = weak.lock()) ++keep->totals.rejected_packets; };
    p->timer = p->loop.every(limits.tick_interval, [weak = std::weak_ptr<Impl>(p)] { if (auto keep = weak.lock()) keep->tick(); }).token;
    if (!p->timer.pending()) { p->stop({}, false, false); return fail(ErrorCode::unavailable, "Core realtime dispatch admission failed"); }
    transmit(p->socket, *link, link->join, true, limits, p->totals, now); return {};
}
Result<std::uint64_t> RealtimeClient::publish(std::uint16_t channel, std::string bytes)
{
    auto p = p_;
    if (p->state != RealtimeState::ready) return fail(ErrorCode::invalid_state, "Realtime client is not ready");
    if (channel >= p->link->channels) return fail(ErrorCode::invalid_argument, "Realtime channel was not negotiated");
    if (p->values[channel] == std::numeric_limits<std::uint64_t>::max()) return fail(ErrorCode::expired, "Realtime value sequence exhausted");
    const auto sequence = p->values[channel] + 1;
    auto queued = enqueue(*p->link, {0, channel}, sequence, std::make_shared<const std::string>(std::move(bytes)), p->limits, p->totals, Clock::now());
    if (!queued) return std::unexpected(queued.error()); p->values[channel] = sequence; return sequence;
}
void RealtimeClient::close() { auto p = p_; p->stop({}, true, true); }
RealtimeState RealtimeClient::state() const { return p_->state; }
std::optional<RealtimePeerInfo> RealtimeClient::info() const
{
    if (p_->state != RealtimeState::ready) return {};
    auto info = p_->link->info; info.round_trip_time = p_->link->rtt; return info;
}
std::optional<Error> RealtimeClient::error() const { return p_->failure; }
std::optional<IpEndpoint> RealtimeClient::local_endpoint() const { return p_->socket.local_endpoint(); }
std::size_t RealtimeClient::pending_bytes() const { return p_->link ? p_->link->pending_bytes : 0; }
RealtimeStatistics RealtimeClient::statistics() const
{
    auto result = p_->totals;
    if (p_->link) { result.round_trip_time = p_->link->rtt; if (p_->state == RealtimeState::ready) result.send_rate_bytes_per_second = static_cast<std::size_t>(p_->link->rate(p_->limits)); }
    return result;
}
} // namespace ii::network
