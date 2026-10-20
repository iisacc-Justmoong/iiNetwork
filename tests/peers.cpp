#include <iiNetwork/Peer.h>
#include <iiJson/Json.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using Value = ii::core::Value;
using namespace std::chrono_literals;
namespace
{
std::filesystem::path fixtures;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T take(Result<T> value) { if (!value) throw std::runtime_error(value.error().message); return std::move(*value); }
void pass(Result<void> value) { if (!value) throw std::runtime_error(value.error().message); }
template<class Predicate> void until(ii::runtime::EventLoop& loop, Predicate done, std::chrono::milliseconds timeout = 5s)
{
    auto end = ii::runtime::Clock::now() + timeout;
    while (!done() && ii::runtime::Clock::now() < end) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(done(), "Peer callback deadline elapsed");
}
IpEndpoint loopback(std::uint16_t port = 0, AddressFamily family = AddressFamily::ipv4)
{ return {IpAddress::loopback(family), port}; }
std::int64_t number(const Value& value) { auto n = value.get<std::int64_t>(); require(n.has_value(), "Expected integer Value"); return n->get(); }
void duplex()
{
    ii::runtime::EventLoop loop; Peer a(loop, "alpha"), b(loop, "beta");
    std::int64_t a_counter = 0, b_counter = 0;
    pass(a.expose("counter.add", [&](PeerCall call, PeerReply reply) { a_counter += number(call.arguments); pass(reply(Value(a_counter))); }));
    pass(b.expose("counter.add", [&](PeerCall call, PeerReply reply) { b_counter += number(call.arguments); pass(reply(Value(b_counter))); }));
    pass(a.listen(loopback())); pass(b.listen(loopback()));
    std::shared_ptr<PeerConnection> accepted;
    b.connected = [&](auto connection) { accepted = std::move(connection); };
    auto dialed = take(a.connect(loopback(b.port())));
    require(dialed->state() != PeerState::ready && !dialed->notify("early", Value{}), "Traffic admitted before mutual hello");
    until(loop, [&] { return accepted && dialed->state() == PeerState::ready; });
    require(dialed->info()->identity == "beta" && accepted->info()->identity == "alpha", "Peer identities");
    require(dialed->info()->local_session == accepted->info()->remote_session && dialed->info()->remote_session == accepted->info()->local_session, "Mutual session exchange");
    bool a_done = false, b_done = false;
    auto a_id = take(dialed->request("counter.add", Value(7), [&](auto result) { require(number(take(std::move(result))) == 7, "Beta operation result"); a_done = true; }));
    auto b_id = take(accepted->request("counter.add", Value(11), [&](auto result) { require(number(take(std::move(result))) == 11, "Alpha operation result"); b_done = true; }));
    require(a_id == b_id, "Test must cover colliding request IDs in opposite directions");
    until(loop, [&] { return a_done && b_done; }); require(a_counter == 11 && b_counter == 7, "Both peers did not control each other");
    unsigned events = 0;
    dialed->received = [&](PeerEvent event) { require(event.topic == "beta.changed", "Dialing peer event topic"); ++events; };
    accepted->received = [&](PeerEvent event) { require(event.topic == "alpha.changed", "Accepting peer event topic"); ++events; };
    pass(dialed->notify("alpha.changed", Value("a"))); pass(accepted->notify("beta.changed", Value("b")));
    until(loop, [&] { return events == 2; });
    // A handler can call back across the same connection before replying.
    pass(b.expose("counter.nested", [&](PeerCall call, PeerReply reply)
    { take(call.connection->request("counter.add", Value(2), [reply](auto result) { pass(reply(std::move(result))); })); }));
    bool nested = false; take(dialed->request("counter.nested", Value{}, [&](auto result) { require(number(take(std::move(result))) == 13, "Nested reverse call result"); nested = true; }));
    until(loop, [&] { return nested; });
    auto reverse = take(b.connect(loopback(a.port())));
    until(loop, [&] { return reverse->state() == PeerState::ready && a.connections().size() == 2; });
    require(b.connections().size() == 2, "A node cannot dial and accept simultaneously");
    b.stop_listening(); require(!b.port() && accepted->state() == PeerState::ready, "Stopping listener closed established peer");
}
void lifecycle()
{
    ii::runtime::EventLoop loop; PeerLimits limits; limits.requests = 1;
    Peer a(loop, "a", limits), b(loop, "b", limits); PeerReply held;
    pass(b.expose("defer", [&](PeerCall, PeerReply reply) { held = reply; })); pass(b.listen(loopback()));
    auto connection = take(a.connect(loopback(b.port()))); until(loop, [&] { return connection->state() == PeerState::ready; });
    bool expired = false;
    take(connection->request("defer", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::expired, "Wrong request timeout"); expired = true; }, 40ms));
    until(loop, [&] { return held.pending(); });
    require(!connection->request("defer", Value{}, [](auto) {}), "Outgoing request bound ignored");
    until(loop, [&] { return expired && held.cancelled(); }); require(!held(Value(1)), "Late reply accepted after timeout");
    held = {}; bool cancelled_completion = false;
    auto id = take(connection->request("defer", Value{}, [&](auto) { cancelled_completion = true; }));
    until(loop, [&] { return held.pending(); }); require(connection->cancel(id) && !connection->cancel(id), "Request cancellation state");
    until(loop, [&] { return held.cancelled(); }); require(!cancelled_completion && !held(Value(2)), "Cancelled request replied or completed");
    held = {}; bool closed = false;
    take(connection->request("defer", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::closed, "Pending call close result"); closed = true; }));
    until(loop, [&] { return held.pending(); }); auto old_session = connection->info()->local_session;
    connection->close(); require(closed, "Close did not settle local outstanding calls");
    until(loop, [&] { return held.cancelled(); });
    auto fresh = take(a.connect(loopback(b.port()))); until(loop, [&] { return fresh->state() == PeerState::ready; });
    require(fresh->info()->local_session != old_session && !held(Value(3)), "Reconnect reused old call/session");
    pass(b.expose("once", [](PeerCall, PeerReply reply) { pass(reply(Value(4))); require(!reply(Value(5)), "Double reply accepted"); }));
    bool once = false; take(fresh->request("once", Value{}, [&](auto result) { require(number(take(std::move(result))) == 4, "Single reply result"); once = true; }));
    until(loop, [&] { return once; });
    held = {}; bool absolute_expired = false;
    take(fresh->request("defer", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::expired, "Delayed polling accepted a late result"); absolute_expired = true; }, 25ms));
    until(loop, [&] { return held.pending(); }); std::this_thread::sleep_for(35ms);
    auto late = held(Value(99)); require(!late && late.error().code == ErrorCode::expired && held.cancelled(), "Reply ignored absolute deadline while loop was idle");
    until(loop, [&] { return absolute_expired; });
    auto doomed = std::make_unique<Peer>(loop, "doomed"); auto retained = std::make_shared<int>(1); auto released = std::weak_ptr<int>(retained);
    pass(doomed->expose("owned", [retained](PeerCall, PeerReply) {})); retained.reset();
    auto last = take(doomed->connect(loopback(b.port())));
    until(loop, [&] { return last->state() == PeerState::ready; }); bool after_destruction = false;
    take(last->request("defer", Value{}, [&](auto) { after_destruction = true; }));
    until(loop, [&] { return held.pending(); }); doomed.reset();
    require(last->state() == PeerState::closed && !after_destruction, "Callbacks escaped node destruction");
    require(released.expired(), "Closed external link retained destroyed node's operation captures");
    // A pending completion may destroy the node while its explicit close is running.
    Peer receiver(loop, "receiver"); std::vector<PeerReply> pending;
    pass(receiver.expose("defer", [&](PeerCall, PeerReply reply) { pending.push_back(reply); })); pass(receiver.listen(loopback()));
    auto closing = std::make_unique<Peer>(loop, "closing"); auto first = take(closing->connect(loopback(receiver.port())));
    auto second = take(closing->connect(loopback(receiver.port())));
    until(loop, [&] { return first->state() == PeerState::ready && second->state() == PeerState::ready; });
    bool extra_callback = false;
    take(first->request("defer", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::closed, "Close reentry result"); closing.reset(); }));
    take(second->request("defer", Value{}, [&](auto) { extra_callback = true; }));
    until(loop, [&] { return pending.size() == 2; }); closing->close();
    require(!closing && !extra_callback && first->state() == PeerState::closed && second->state() == PeerState::closed, "Node close/destruction reentry escaped lifetime boundary");
}
void policy()
{
    ii::runtime::EventLoop loop; Peer a(loop, "a"), b(loop, "b"); unsigned invoked = 0;
    pass(a.expose("admin.write", [&](PeerCall, PeerReply reply) { ++invoked; pass(reply(Value(true))); }));
    pass(b.expose("admin.write", [&](PeerCall, PeerReply reply) { ++invoked; pass(reply(Value(true))); }));
    require(!b.expose("admin.write", [](auto, auto) {}) && !b.expose("bad operation", [](auto, auto) {}), "Invalid/duplicate operation accepted");
    a.authorize([](const PeerInfo&, std::string_view) { return false; });
    b.authorize([](const PeerInfo& peer, std::string_view) { return peer.identity == "a"; });
    std::shared_ptr<PeerConnection> accepted; b.connected = [&](auto c) { accepted = std::move(c); };
    pass(b.listen(loopback())); auto link = take(a.connect(loopback(b.port())));
    until(loop, [&] { return accepted && link->state() == PeerState::ready; });
    unsigned done = 0;
    take(accepted->request("admin.write", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::permission_denied, "Accepting side gained privilege"); ++done; }));
    take(link->request("admin.write", Value{}, [&](auto result) { require(take(std::move(result)) == Value(true), "Registered operation rejected"); ++done; }));
    take(link->request("missing", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::not_found, "Unknown operation result"); ++done; }));
    pass(b.expose("throws", [](auto, auto) { throw std::runtime_error("private implementation detail"); }));
    take(link->request("throws", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::remote_error && result.error().message.find("private") == std::string::npos, "Handler exception leaked or failed connection"); ++done; }));
    until(loop, [&] { return done == 4; }); require(invoked == 1 && link->state() == PeerState::ready, "Denied/unexposed handler ran");
    require(b.remove_operation("admin.write") && !b.remove_operation("admin.write"), "Operation removal");
    PeerLimits invalid; invalid.frame_bytes = 1; Peer unusable(loop, "invalid", invalid);
    require(!unusable.listen(loopback()) && !unusable.connect(loopback(b.port())), "Invalid peer limits admitted");
    Peer invalid_identity(loop, std::string(1, '\xff')); require(!invalid_identity.listen(loopback()), "Invalid UTF-8 peer identity admitted");
    PeerLimits small; small.frame_bytes = 512; small.pending_bytes = 1024; small.requests = 1;
    Peer constrained(loop, "constrained", small); PeerReply waiting;
    pass(constrained.expose("defer", [&](PeerCall, PeerReply reply) { waiting = reply; })); pass(constrained.listen(loopback()));
    auto bounded = take(a.connect(loopback(constrained.port()))); until(loop, [&] { return bounded->state() == PeerState::ready; });
    bool rejected_callback = false;
    auto oversized = bounded->request("defer", Value(std::string(600, 'x')), [&](auto) { rejected_callback = true; });
    require(!oversized && oversized.error().code == ErrorCode::too_large && !bounded->pending_requests() && !rejected_callback, "Negotiated frame bound ignored");
    auto held_id = take(bounded->request("defer", Value{}, [](auto) {})); until(loop, [&] { return waiting.pending(); });
    bool busy = false; take(bounded->request("defer", Value{}, [&](auto result) { require(!result && result.error().code == ErrorCode::would_block, "Incoming call bound ignored"); busy = true; }));
    until(loop, [&] { return busy; }); require(waiting.pending() && bounded->state() == PeerState::ready, "Incoming call pressure closed or displaced admitted operation");
    require(bounded->cancel(held_id), "Bounded call cancel"); until(loop, [&] { return waiting.cancelled(); });
}
std::string frame(std::string text)
{
    std::string result; for (unsigned i = 4; i; --i) result += static_cast<char>(text.size() >> ((i - 1) * 8)); return result + text;
}
std::string hello(std::string version = "1")
{ return frame("{\"type\":\"hello\",\"version\":" + version + ",\"identity\":\"raw\",\"session\":\"" + take(SessionId::generate()).string() + "\",\"maximum_frame\":1048576}"); }
void protocol()
{
    ii::runtime::EventLoop loop;
    for (auto attack : {0, 1, 2, 3, 4, 5})
    {
        Peer node(loop, "node"); pass(node.listen(loopback())); Tcp raw(loop);
        unsigned failed = 0; node.failed = [&](auto, auto) { ++failed; };
        pass(raw.connect(loopback(node.port()))); until(loop, [&] { return raw.is_connected(); });
        std::string bytes;
        if (attack == 0) bytes = frame("{\"type\":\"event\",\"topic\":\"early\",\"value\":null}");
        if (attack == 1) bytes = hello("2");
        if (attack == 2) bytes = std::string("\x7f\xff\xff\xff", 4);
        if (attack == 3) bytes = frame("{bad json");
        if (attack == 4) bytes = hello() + hello();
        if (attack == 5) bytes = hello() + frame("{\"type\":\"result\",\"id\":\"999\",\"value\":null}");
        require(raw.write(bytes), "Raw peer attack send"); until(loop, [&] { return failed == 1; });
        require(node.connections().empty(), "Malformed peer retained");
    }
    PeerLimits limits; limits.handshake_timeout = 30ms; Peer silent(loop, "timeout", limits); pass(silent.listen(loopback()));
    bool timed_out = false; silent.failed = [&](auto, Error error) { timed_out = error.code == ErrorCode::expired; };
    Tcp raw(loop); pass(raw.connect(loopback(silent.port()))); until(loop, [&] { return timed_out; });
    Peer node(loop, "fragmented"); pass(node.listen(loopback())); Tcp sender(loop);
    pass(sender.connect(loopback(node.port()))); until(loop, [&] { return sender.is_connected(); });
    unsigned ready = 0, events = 0; node.connected = [&](auto link) { ++ready; link->received = [&](auto event) { require(event.value == Value("ok"), "Fragmented event value"); ++events; }; };
    auto bytes = hello() + frame("{\"type\":\"event\",\"topic\":\"changed\",\"value\":\"ok\"}");
    for (char byte : bytes) { require(sender.write(std::string(1, byte)), "Fragmented frame send"); loop.poll(); }
    until(loop, [&] { return ready == 1 && events == 1; });
    Peer full_duplex(loop, "full-duplex"); ListenerOptions half_close;
    half_close.accepted_socket.stream.allow_half_close = true; pass(full_duplex.listen(loopback(), half_close));
    Tcp half_closed(loop); pass(half_closed.connect(loopback(full_duplex.port())));
    until(loop, [&] { return half_closed.is_connected(); }); require(half_closed.write(hello()), "Half-close peer hello");
    until(loop, [&] { return full_duplex.connections().size() == 1 && full_duplex.connections().front()->state() == PeerState::ready; });
    pass(half_closed.shutdown_write());
    until(loop, [&] { return full_duplex.connections().empty(); });
}
TlsOptions tls_options(bool server)
{
    TlsOptions options; options.policy.ca_file = (fixtures/"ca.pem").string();
    auto name = server ? "server" : "client";
    options.policy.identity = {(fixtures/(std::string(name)+".pem")).string(), (fixtures/(std::string(name)+".key")).string(), {}};
    options.require_client_certificate = server; options.alpn_protocols = {"iin-peer/1"}; return options;
}
void transports()
{
    ii::runtime::EventLoop loop;
    for (auto transport : {0, 1, 2})
    {
        Peer a(loop, "a"), b(loop, "b");
        pass(a.expose("echo", [](PeerCall call, PeerReply reply) { pass(reply(call.arguments)); }));
        pass(b.expose("echo", [](PeerCall call, PeerReply reply) { pass(reply(call.arguments)); }));
        std::shared_ptr<PeerConnection> accepted; b.connected = [&](auto c) { accepted = std::move(c); };
        std::shared_ptr<PeerConnection> link;
        if (transport == 0)
        { pass(b.listen(loopback(0, AddressFamily::ipv6))); link = take(a.connect(loopback(b.port(), AddressFamily::ipv6))); }
        if (transport == 1)
        {
            auto path = (fixtures/"peer.sock").string(); std::filesystem::remove(path);
            pass(b.listen_local({path})); link = take(a.connect_local({path}));
        }
        if (transport == 2)
        {
            pass(b.listen_tls(loopback(), take(TlsContext::server(tls_options(true)))));
            link = take(a.connect_tls(loopback(b.tls_port()), "localhost", take(TlsContext::client(tls_options(false)))));
        }
        until(loop, [&] { return accepted && link->state() == PeerState::ready; });
        unsigned completed = 0;
        take(link->request("echo", Value("forward"), [&](auto value) { require(take(std::move(value)) == Value("forward"), "Transport forward result"); ++completed; }));
        take(accepted->request("echo", Value("reverse"), [&](auto value) { require(take(std::move(value)) == Value("reverse"), "Transport reverse result"); ++completed; }));
        until(loop, [&] { return completed == 2; });
        if (transport == 2) require(link->info()->tls->peer_verified && accepted->info()->tls->peer_verified, "Peer mutual TLS evidence");
#ifndef _WIN32
        if (transport == 1) require(link->info()->local_credentials.has_value(), "Peer local credentials");
#endif
    }
}
}
int main(int argc, char** argv)
{
    try
    {
        require(argc == 3, "Expected peer case and fixture path"); fixtures = std::filesystem::absolute(argv[2]);
        std::string name = argv[1];
        if (name == "duplex") duplex(); else if (name == "lifecycle") lifecycle(); else if (name == "policy") policy();
        else if (name == "protocol") protocol(); else if (name == "transports") transports(); else throw std::runtime_error("Unknown peer test");
        std::cout << "PASS peers." << name << '\n'; return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
