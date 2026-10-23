#include <iiNetwork/Realtime.h>
#include <charconv>
#include <iostream>
#include <stdexcept>

using namespace ii::network;
using namespace std::chrono_literals;
namespace
{
void pass(Result<void> value) { if (!value) throw std::runtime_error(value.error().message); }
template<class T> T take(Result<T> value) { if (!value) throw std::runtime_error(value.error().message); return std::move(*value); }
// This test-only record travels over private anonymous process pipes. The
// supervising Python fixture never writes credentials to logs or files.
void admission(std::uint16_t port, const RealtimeTicket& ticket)
{
    constexpr char digits[] = "0123456789abcdef"; std::string key;
    for (auto b : ticket.key) { key += digits[b >> 4]; key += digits[b & 15]; }
    std::cout << port << ' ' << ticket.id.string() << ' ' << ticket.peer << ' ' << ticket.room << ' ' << key << std::endl;
}
int serve()
{
    ii::runtime::EventLoop loop; RealtimeServer server(loop); pass(server.listen());
    auto a = take(server.issue("isolated-process-room")), b = take(server.issue("isolated-process-room"));
    admission(server.port(), a); admission(server.port(), b);
    unsigned joined = 0, left = 0, relayed = 0; bool failed = false;
    server.connected = [&](auto) { ++joined; };
    server.received = [&](const RealtimeFrame& frame) {
        const auto recipients = server.relay(frame);
        if (!recipients) { failed = true; loop.request_stop(); }
        else relayed += static_cast<unsigned>(*recipients);
    };
    server.disconnected = [&](auto, auto) { if (++left == 2) loop.request_stop(); };
    const auto timeout = loop.after(15s, [&] { failed = true; loop.request_stop(); });
    if (!timeout) throw std::runtime_error("Process fixture timer admission failed");
    loop.run(); timeout.token.cancel();
    if (failed || joined != 2 || left != 2 || relayed < 60) throw std::runtime_error("Independent realtime server exchange failed");
    std::cout << "SERVER_OK\n"; return 0;
}
int participate()
{
    unsigned port = 0; RealtimeTicket ticket; std::string id, key; RealtimePeerId other = 0;
    if (!(std::cin >> port >> id >> ticket.peer >> ticket.room >> key >> other) || !port || port > 65535 || key.size() != 64)
        throw std::runtime_error("Invalid private process admission");
    ticket.id = take(SessionId::parse(id));
    for (unsigned i = 0; i < 32; ++i) {
        unsigned value = 0; const auto first = key.data() + i * 2;
        auto [end, code] = std::from_chars(first, first + 2, value, 16);
        if (code != std::errc{} || end != first + 2) throw std::runtime_error("Invalid private process credential");
        ticket.key[i] = static_cast<unsigned char>(value);
    }
    ii::runtime::EventLoop loop; RealtimeClient client(loop);
    unsigned received = 0, sent = 0; bool failed = false;
    std::optional<ii::runtime::Clock::time_point> completed;
    client.received = [&](const RealtimeFrame& frame) {
        if (frame.peer != other || frame.room != ticket.room || frame.bytes != std::to_string(frame.sequence)) failed = true;
        ++received;
    };
    client.failed = [&](auto) { failed = true; loop.request_stop(); };
    pass(client.connect({IpAddress::loopback(), static_cast<std::uint16_t>(port)}, ticket));
    const auto updates = loop.every(16ms, [&] {
        if (client.state() != RealtimeState::ready) return;
        if (received >= 30) {
            if (!completed) completed = ii::runtime::Clock::now();
            if (ii::runtime::Clock::now() - *completed >= 200ms) { loop.request_stop(); return; }
        }
        if (!client.publish(0, std::to_string(++sent))) { failed = true; loop.request_stop(); }
    });
    const auto timeout = loop.after(5s, [&] { failed = true; loop.request_stop(); });
    if (!updates || !timeout) throw std::runtime_error("Client fixture timer admission failed");
    loop.run(); updates.token.cancel(); timeout.token.cancel(); client.close();
    if (failed || received < 30) throw std::runtime_error("Independent realtime participant exchange failed");
    std::cout << "CLIENT_OK\n"; return 0;
}
}
int main(int argc, char** argv)
{
    try {
        if (argc != 2) throw std::runtime_error("Expected isolated fixture role");
        const std::string role = argv[1];
        if (role == "server") return serve();
        if (role == "client") return participate();
        throw std::runtime_error("Invalid isolated fixture role");
    } catch (const std::exception& exception) { std::cerr << exception.what() << '\n'; return 1; }
}
