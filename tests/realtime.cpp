#include <iiNetwork/Realtime.h>
#include <iiNetwork/Wire.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace
{
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T take(Result<T> value) { if (!value) throw std::runtime_error(value.error().message); return std::move(*value); }
void pass(Result<void> value) { if (!value) throw std::runtime_error(value.error().message); }
IpEndpoint endpoint(std::uint16_t port = 0) { return {IpAddress::loopback(), port}; }
template<class Predicate> void until(ii::runtime::EventLoop& loop, Predicate predicate, std::chrono::milliseconds timeout = 3s)
{
    const auto end = ii::runtime::Clock::now() + timeout;
    while (!predicate() && ii::runtime::Clock::now() < end) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(predicate(), "Realtime callback deadline elapsed");
}
void dispatch(ii::runtime::EventLoop& loop, std::chrono::milliseconds duration)
{
    const auto end = ii::runtime::Clock::now() + duration;
    while (ii::runtime::Clock::now() < end) { loop.poll(); std::this_thread::sleep_for(1ms); }
}
struct Proxy
{
    Udp socket; IpEndpoint server; std::optional<IpEndpoint> client;
    std::function<bool(bool, const std::string&)> intercept;
    Proxy(ii::runtime::EventLoop& loop, IpEndpoint upstream) : socket(loop), server(upstream)
    {
        pass(socket.bind(endpoint()));
        socket.received = [&](Datagram packet) {
            const bool downstream = packet.sender == server;
            if (!downstream) client = packet.sender;
            if (intercept && intercept(downstream, packet.bytes)) return;
            if (downstream && client) pass(socket.send(packet.bytes, *client));
            else if (!downstream) pass(socket.send(packet.bytes, server));
        };
    }
    IpEndpoint address() const { return endpoint(socket.port()); }
};
unsigned kind(const std::string& packet) { return packet.size() > 5 ? static_cast<unsigned char>(packet[5]) : 0; }

void rooms()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen());
    const auto a_ticket = take(server.issue("shared")), b_ticket = take(server.issue("shared")), c_ticket = take(server.issue("private"));
    RealtimeClient a(loop), b(loop), c(loop); std::vector<RealtimeFrame> af, bf, cf;
    a.received = [&](auto frame) { af.push_back(std::move(frame)); };
    b.received = [&](auto frame) { bf.push_back(std::move(frame)); };
    c.received = [&](auto frame) { cf.push_back(std::move(frame)); };
    unsigned relays = 0; server.received = [&](auto frame) { require(take(server.relay(frame)) == 1, "room relay recipient count"); ++relays; };
    pass(a.connect(endpoint(server.port()), a_ticket)); pass(b.connect(endpoint(server.port()), b_ticket)); pass(c.connect(endpoint(server.port()), c_ticket));
    require(!a.publish(0, "early"), "data admitted before authenticated welcome");
    until(loop, [&] { return a.state() == RealtimeState::ready && b.state() == RealtimeState::ready && c.state() == RealtimeState::ready; });
    require(server.peers().size() == 3 && server.pending_tickets() == 0, "membership state");
    const std::string binary("position\0\xff", 10); const auto sequence = take(a.publish(0, binary));
    until(loop, [&] { return bf.size() == 1; }); dispatch(loop, 20ms);
    require(relays == 1 && af.empty() && cf.empty(), "relay crossed room or echoed to sender");
    require(bf[0].peer == a_ticket.peer && bf[0].room == "shared" && bf[0].sequence == sequence && bf[0].bytes == binary, "authenticated binary origin/sequence");
    require(take(server.broadcast("shared", 1, "world snapshot")) == 2, "server broadcast recipients");
    until(loop, [&] { return af.size() == 1 && bf.size() == 2; });
    require(af[0].peer == 0 && af[0].channel == 1 && cf.empty(), "server publication identity or room");
    take(server.send(c_ticket.peer, 2, "private snapshot")); until(loop, [&] { return cf.size() == 1; });
    require(cf[0].peer == 0 && cf[0].room == "private", "targeted server publication");
    require(!a.connect(endpoint(server.port()), a_ticket) && a.state() == RealtimeState::ready, "live connect replaced session");
    require(!server.listen() && server.peers().size() == 3, "live listen replaced memberships");
}

void ordering()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen()); auto ticket = take(server.issue("ordering"));
    Proxy proxy(loop, endpoint(server.port())); RealtimeClient client(loop); std::vector<std::string> held; std::vector<RealtimeFrame> frames;
    server.received = [&](auto frame) { frames.push_back(std::move(frame)); };
    proxy.intercept = [&](bool downstream, const auto& bytes) { if (!downstream && kind(bytes) == 3) { held.push_back(bytes); return true; } return false; };
    pass(client.connect(proxy.address(), ticket)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    take(client.publish(0, "old")); until(loop, [&] { return held.size() == 1; });
    take(client.publish(0, "latest")); until(loop, [&] { return held.size() == 2; });
    take(client.publish(1, "independent")); until(loop, [&] { return held.size() == 3; });
    pass(proxy.socket.send(held[1], proxy.server)); pass(proxy.socket.send(held[0], proxy.server));
    pass(proxy.socket.send(held[0], proxy.server)); pass(proxy.socket.send(held[2], proxy.server));
    until(loop, [&] { return frames.size() == 2; }); dispatch(loop, 20ms);
    require(frames.size() == 2 && frames[0].bytes == "latest" && frames[1].bytes == "independent", "reorder/duplicate regressed state or blocked another channel");
    require(server.statistics().stale_frames > 0 && server.statistics().rejected_packets > 0, "stale/replay observations missing");
}

void bounds()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.payload_bytes = 32; limits.pending_bytes = 32; limits.pending_frames = 1;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); RealtimeClient client(loop); auto ticket = take(server.issue("bounds"));
    std::vector<RealtimeFrame> frames; server.received = [&](auto frame) { frames.push_back(std::move(frame)); };
    pass(client.connect(endpoint(server.port()), ticket, limits)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    for (unsigned i = 0; i < 1000; ++i) take(client.publish(0, std::to_string(i)));
    require(client.pending_bytes() == 3 && client.statistics().coalesced_frames == 999, "latest-value queue grew or lost coalescing");
    auto full = client.publish(1, "another stream"); require(!full && full.error().code == ErrorCode::would_block, "pending-frame bound");
    require(!client.publish(0, std::string(33, 'x')) && !client.publish(16, "invalid"), "negotiated payload/channel bound");
    until(loop, [&] { return frames.size() == 1; }); require(frames[0].bytes == "999" && frames[0].sequence == 1000, "coalesced state delivery");
    auto invalid = limits; invalid.payload_bytes = 1101; RealtimeServer invalid_server(loop);
    require(!invalid_server.listen(endpoint(), invalid), "fragmenting payload admitted");
    invalid = limits; invalid.idle_timeout = invalid.heartbeat_interval;
    require(!invalid_server.listen(endpoint(), invalid), "invalid lifetime limits admitted");
    RealtimeLimits one; one.peers = 1; RealtimeServer capacity(loop); pass(capacity.listen(endpoint(), one));
    take(capacity.issue("room", 20ms)); require(!capacity.issue("room"), "ticket/session capacity ignored");
    until(loop, [&] { return capacity.pending_tickets() == 0; }); take(capacity.issue("room"));
    ii::runtime::EventLoop tiny(1); RealtimeServer unavailable(tiny);
    const auto denied = unavailable.listen();
    require(!denied && denied.error().code == ErrorCode::unavailable && !unavailable.listening(), "runtime timer admission leaked live socket");
    tiny.poll(); Udp reclaimed(tiny); pass(reclaimed.bind(endpoint()));
}

void authentication()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen()); auto ticket = take(server.issue("secure"));
    Proxy proxy(loop, endpoint(server.port())); RealtimeClient client(loop); std::vector<std::string> packets; unsigned delivered = 0;
    proxy.intercept = [&](bool down, const auto& bytes) { if (!down && kind(bytes) == 3) packets.push_back(bytes); return false; };
    server.received = [&](auto) { ++delivered; };
    pass(client.connect(proxy.address(), ticket)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    take(client.publish(0, "valid")); until(loop, [&] { return delivered == 1 && !packets.empty(); });
    Udp impostor(loop); pass(impostor.bind(endpoint())); pass(impostor.send(packets[0], proxy.server));
    auto altered = packets[0]; altered.back() ^= 1; pass(proxy.socket.send(altered, proxy.server));
    pass(proxy.socket.send(packets[0], proxy.server));
    // A valid credential cannot assert another participant's source ID or
    // poison replay state with a malformed, authenticated high sequence.
    std::string header = packets[0].substr(0, 24); wire::append_be(header, 100000, 8);
    std::string body; wire::append_be(body, 999, 8); wire::append_be(body, 0, 2); wire::append_be(body, 2, 8); body += "spoof";
    Aes256Gcm cipher(ticket.key); auto forged = take(cipher.seal(body, header)); pass(proxy.socket.send(header + forged, proxy.server));
    dispatch(loop, 20ms); require(delivered == 1 && server.peers().size() == 1, "forged/replayed traffic reached application or replaced peer");
    take(client.publish(0, "still valid")); until(loop, [&] { return delivered == 2; });
    auto wrong = take(server.issue("secure")); wrong.key[0] ^= 1; RealtimeClient denied(loop); RealtimeLimits fast;
    fast.handshake_timeout = 100ms; fast.retry_interval = 20ms; bool rejected = false;
    denied.failed = [&](Error error) { rejected = error.code == ErrorCode::expired; };
    pass(denied.connect(endpoint(server.port()), wrong, fast)); until(loop, [&] { return rejected; });
    require(server.peers().size() == 1 && server.statistics().rejected_packets >= 4, "invalid credential created session");
}

void lifecycle()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.tick_interval = 1ms; limits.retry_interval = 20ms;
    limits.heartbeat_interval = 20ms; limits.idle_timeout = 150ms; limits.handshake_timeout = 500ms; limits.maximum_frame_age = 100ms;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); auto ticket = take(server.issue("lifetime"));
    Proxy proxy(loop, endpoint(server.port())); unsigned joins = 0, welcomes = 0, accepted = 0, ready = 0;
    bool blackhole = false; proxy.intercept = [&](bool down, const auto& bytes) {
        if (blackhole) return true;
        if (!down && kind(bytes) == 1 && ++joins == 1) return true;
        if (down && kind(bytes) == 2 && ++welcomes == 1) return true;
        return false;
    };
    server.connected = [&](auto) { ++accepted; }; RealtimeClient client(loop); client.connected = [&] { ++ready; };
    pass(client.connect(proxy.address(), ticket, limits)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    require(joins >= 3 && welcomes >= 2 && accepted == 1 && ready == 1, "handshake retry duplicated membership or lost welcome");
    dispatch(loop, 450ms); require(client.state() == RealtimeState::ready && server.peers().size() == 1, "heartbeats did not keep idle participants alive");
    require(client.statistics().round_trip_time.count() > 0, "heartbeat RTT observation");
    blackhole = true; until(loop, [&] { return client.state() == RealtimeState::failed && server.peers().empty(); });
    RealtimeClient reused(loop); auto short_limits = limits; short_limits.handshake_timeout = 100ms;
    pass(reused.connect(endpoint(server.port()), ticket, short_limits)); until(loop, [&] { return reused.state() == RealtimeState::failed; });
    require(server.peers().empty(), "consumed ticket re-established expired session");
    auto fresh = take(server.issue("lifetime")); RealtimeClient renewed(loop); pass(renewed.connect(endpoint(server.port()), fresh, limits));
    until(loop, [&] { return renewed.state() == RealtimeState::ready; });
    require(server.revoke(fresh.peer), "revoke"); until(loop, [&] { return renewed.state() != RealtimeState::ready; });
    require(!server.revoke(fresh.peer) && server.peers().empty(), "revoked session retained");
}

void lifetime()
{
    ii::runtime::EventLoop loop; auto server = std::make_unique<RealtimeServer>(loop); pass(server->listen());
    auto ticket = take(server->issue("owned")); RealtimeClient client(loop); pass(client.connect(endpoint(server->port()), ticket));
    until(loop, [&] { return client.state() == RealtimeState::ready; });
    server->received = [&](auto) { server.reset(); };
    take(client.publish(0, "destroy owner")); until(loop, [&] { return !server && client.state() != RealtimeState::ready; });
    RealtimeServer other(loop); pass(other.listen()); auto mine = std::make_unique<RealtimeClient>(loop);
    auto second = take(other.issue("owned")); pass(mine->connect(endpoint(other.port()), second));
    until(loop, [&] { return mine->state() == RealtimeState::ready; });
    bool escaped = false; mine->failed = [&](auto) { mine.reset(); }; mine->disconnected = [&] { escaped = true; };
    other.revoke(second.peer); until(loop, [&] { return !mine; }); require(!escaped, "callback escaped destruction during failure");
}

void negotiation()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.channels = 4; limits.payload_bytes = 64;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); auto ticket = take(server.issue(std::string(128, 'r')));
    RealtimeClient client(loop); auto small = limits; small.channels = 2; small.payload_bytes = 16;
    pass(client.connect(endpoint(server.port()), ticket, small)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    require(!client.publish(2, "invalid") && !client.publish(0, std::string(17, 'x')), "client ignored negotiated minimum");
    require(!server.send(ticket.peer, 2, "invalid") && !server.send(ticket.peer, 0, std::string(17, 'x')), "server ignored negotiated minimum");
    require(take(server.broadcast(ticket.room, 3, "unavailable channel")) == 0, "fanout ignored receiver channel capabilities");
    unsigned received = 0; client.received = [&](auto frame) { require(frame.bytes == std::string(16, 'x') && frame.room == ticket.room, "maximum room/payload encoding"); ++received; };
    take(server.send(ticket.peer, 1, std::string(16, 'x'))); until(loop, [&] { return received == 1; });
}

void pacing()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.bytes_per_second = 1200;
    limits.maximum_frame_age = 20ms; limits.heartbeat_interval = 25ms;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); auto ticket = take(server.issue("paced"));
    RealtimeClient client(loop); unsigned received = 0; server.received = [&](auto) { ++received; };
    pass(client.connect(endpoint(server.port()), ticket, limits)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    for (std::uint16_t channel = 0; channel < 4; ++channel) take(client.publish(channel, std::string(1024, 'x')));
    until(loop, [&] { return client.pending_bytes() == 0; });
    require(client.statistics().sent_frames <= 2 && client.statistics().expired_frames >= 2, "rate pacing accumulated or transmitted obsolete snapshots");
    dispatch(loop, 150ms); require(received <= 2 && client.state() == RealtimeState::ready && client.statistics().round_trip_time.count() > 0,
                                 "data pressure blocked liveness control");

    RealtimeServer responsive(loop); RealtimeLimits adaptive; adaptive.heartbeat_interval = 25ms;
    pass(responsive.listen(endpoint(), adaptive)); auto admitted = take(responsive.issue("adaptive"));
    Proxy proxy(loop, endpoint(responsive.port())); RealtimeClient publisher(loop); unsigned frames = 0, data_packets = 0;
    responsive.received = [&](auto) { ++frames; };
    proxy.intercept = [&](bool down, const auto& bytes) {
        if (!down && kind(bytes) == 3) { ++data_packets; return data_packets >= 2 && data_packets <= 4; }
        return false;
    };
    pass(publisher.connect(proxy.address(), admitted, adaptive)); until(loop, [&] { return publisher.state() == RealtimeState::ready; });
    const auto updates = loop.every(3ms, [&] { take(publisher.publish(0, "live state")); }); require(bool(updates), "adaptive update timer");
    until(loop, [&] { return frames >= 10 && publisher.statistics().congestion_events > 0; }); updates.token.cancel();
    require(publisher.state() == RealtimeState::ready, "packet loss disconnected latest-value stream");
}

void feedback_timeout()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.heartbeat_interval = 25ms;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); auto ticket = take(server.issue("feedback"));
    Proxy proxy(loop, endpoint(server.port())); RealtimeClient client(loop); bool suppress = true;
    proxy.intercept = [&](bool down, const auto& bytes) { return suppress && down && (kind(bytes) == 4 || kind(bytes) == 5); };
    pass(client.connect(proxy.address(), ticket, limits)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    const auto snapshots = loop.every(20ms, [&] { take(server.broadcast("feedback", 0, "server snapshot")); });
    require(bool(snapshots), "feedback snapshot timer");
    dispatch(loop, 450ms);
    require(client.state() == RealtimeState::ready && client.statistics().congestion_events > 0 && client.statistics().send_rate_bytes_per_second <= 1200,
            "fresh inbound data hid absent outbound delivery feedback");
    suppress = false; until(loop, [&] { return client.statistics().round_trip_time.count() > 0 && client.statistics().send_rate_bytes_per_second > 1200; });
    snapshots.token.cancel();
}

void delayed_rtt()
{
    ii::runtime::EventLoop loop; RealtimeLimits limits; limits.heartbeat_interval = 20ms; limits.idle_timeout = 500ms;
    RealtimeServer server(loop); pass(server.listen(endpoint(), limits)); auto ticket = take(server.issue("delayed-rtt"));
    Proxy proxy(loop, endpoint(server.port())); RealtimeClient client(loop);
    std::vector<std::pair<ii::runtime::Clock::time_point,std::string>> delayed;
    proxy.intercept = [&](bool down, const auto& bytes) {
        if (down && kind(bytes) == 5) { delayed.emplace_back(ii::runtime::Clock::now() + 80ms, bytes); return true; }
        return false;
    };
    const auto release = loop.every(5ms, [&] {
        const auto now = ii::runtime::Clock::now();
        while (!delayed.empty() && delayed.front().first <= now) {
            pass(proxy.socket.send(delayed.front().second, *proxy.client)); delayed.erase(delayed.begin());
        }
    });
    require(bool(release), "delayed RTT timer");
    pass(client.connect(proxy.address(), ticket, limits)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    until(loop, [&] { return client.statistics().round_trip_time >= 70ms; });
    require(client.state() == RealtimeState::ready, "RTT longer than heartbeat interval disconnected participant");
    release.token.cancel();
}

void reentry()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen());
    const auto first = take(server.issue("reentry")), second = take(server.issue("reentry")), third = take(server.issue("reentry"));
    RealtimeClient client(loop); unsigned escaped = 0;
    client.failed = [&](auto) { pass(client.connect(endpoint(server.port()), second)); };
    client.disconnected = [&] { ++escaped; };
    pass(client.connect(endpoint(server.port()), first)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    server.revoke(first.peer);
    until(loop, [&] { return client.state() == RealtimeState::ready && client.info()->peer == second.peer; });
    require(escaped == 0, "old failure emitted disconnect after reentrant connect");
    unsigned failures = 0; client.failed = [&](auto) { ++failures; };
    client.received = [&](auto) {
        client.close(); pass(client.connect(endpoint(server.port()), third));
        throw std::runtime_error("old callback exception");
    };
    take(server.send(second.peer, 0, "switch session"));
    until(loop, [&] { return client.state() == RealtimeState::ready && client.info()->peer == third.peer; });
    require(failures == 0 && escaped == 1, "old callback failure closed replacement session");
}

void protocol()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen()); auto ticket = take(server.issue("protocol"));
    Proxy proxy(loop, endpoint(server.port())); RealtimeClient client(loop); std::string valid; unsigned received = 0;
    server.received = [&](auto) { ++received; };
    proxy.intercept = [&](bool down, const auto& bytes) { if (!down && kind(bytes) == 3) valid = bytes; return false; };
    pass(client.connect(proxy.address(), ticket)); until(loop, [&] { return client.state() == RealtimeState::ready; });
    take(client.publish(0, "valid")); until(loop, [&] { return received == 1 && !valid.empty(); });
    for (unsigned attack = 0; attack < 6; ++attack)
    {
        auto packet = valid;
        if (attack == 0) packet.resize(20);
        if (attack == 1) packet[4] = 2;
        if (attack == 2) packet[5] = 127;
        if (attack == 3) packet[6] = 1;
        if (attack == 4) packet[7] = 1;
        if (attack == 5) packet = std::string(1400, 'x');
        pass(proxy.socket.send(packet, proxy.server));
    }
    dispatch(loop, 30ms); require(received == 1 && server.statistics().rejected_packets >= 6, "malformed protocol reached application");
    take(client.publish(0, "still alive")); until(loop, [&] { return received == 2; });
    server.received = [](auto) { throw std::runtime_error("private handler detail"); };
    bool contained = false; client.failed = [&](auto error) { contained = error.message.find("private") == std::string::npos; };
    take(client.publish(0, "trigger")); until(loop, [&] { return contained && server.peers().empty(); });
}
}
int main(int argc, char** argv)
{
    try {
        require(argc == 2, "expected realtime test case"); const std::string test = argv[1];
        if (test == "rooms") rooms(); else if (test == "ordering") ordering(); else if (test == "bounds") bounds();
        else if (test == "authentication") authentication(); else if (test == "lifecycle") lifecycle(); else if (test == "lifetime") lifetime();
        else if (test == "negotiation") negotiation(); else if (test == "pacing") pacing(); else if (test == "feedback") feedback_timeout();
        else if (test == "reentry") reentry(); else if (test == "protocol") protocol();
        else if (test == "rtt") delayed_rtt();
        else throw std::runtime_error("unknown realtime case");
        std::cout << "PASS realtime." << test << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
