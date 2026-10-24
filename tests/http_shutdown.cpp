#include <iiNetwork/Server.h>
#include <iiNetwork/Transport.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class Predicate>
void until(ii::runtime::EventLoop& loop, Predicate predicate, std::chrono::milliseconds budget = 3s) {
    const auto end = ii::runtime::Clock::now() + budget;
    while (!predicate() && ii::runtime::Clock::now() < end) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(predicate(), "HTTP shutdown test deadline elapsed");
}
IpEndpoint endpoint(std::uint16_t port = 0) { return {IpAddress::loopback(), port}; }
void graceful() {
    ii::runtime::EventLoop loop;
    HttpServer server(loop); unsigned calls = 0;
    const auto handler = [&](const ServerRequest& request) { ++calls; return ServerResponse{200, {}, request.body}; };
    require(server.listen(endpoint(), handler), "listen"); const auto port = server.port();
    Tcp client(loop); std::string reply; client.readable = [&] { reply += client.read(); };
    require(bool(client.connect(endpoint(port))), "connect");
    until(loop, [&] { return client.is_connected() && server.active_connections() == 1; });
    require(client.write("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nab"), "partial request");
    for (int i = 0; i < 10; ++i) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(!server.shutdown(-1ms) && server.listening(), "invalid shutdown changed listener");
    require(bool(server.shutdown(500ms)), "graceful shutdown");
    require(!server.listening() && server.draining(), "shutdown state");
    require(bool(server.shutdown(10s)), "idempotent shutdown");
    Tcp late(loop); bool rejected = false; late.failed = [&](auto) { rejected = true; };
    auto dial = late.connect(endpoint(port));
    // Refusal notification can take longer than the drain grace on Windows.
    // Complete the admitted request without waiting for that unrelated dial.
    require(client.write("cd"), "complete request while draining");
    until(loop, [&] { return server.active_connections() == 0 && !client.is_connected(); });
    require(calls == 1 && reply.find("200 Response") != reply.npos && reply.ends_with("abcd"), "in-flight response lost");
    require(!server.draining(), "drain did not finish");
    if (dial) until(loop, [&] { return rejected; });
    require(!late.is_connected(), "accepted after shutdown");
    require(server.listen(endpoint(), handler), "restart after graceful shutdown"); server.close();
}
void forced_deadline() {
    ii::runtime::EventLoop loop;
    HttpServer server(loop); unsigned calls = 0;
    require(server.listen(endpoint(), [&](const auto&) { ++calls; return ServerResponse{}; }), "listen");
    Tcp held(loop); require(bool(held.connect(endpoint(server.port()))), "connect");
    until(loop, [&] { return held.is_connected() && server.active_connections() == 1; });
    require(held.write("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n"), "incomplete request");
    const auto start = ii::runtime::Clock::now();
    require(bool(server.shutdown(35ms)), "shutdown deadline");
    require(bool(server.shutdown(5s)), "repeat shutdown");
    until(loop, [&] { return !server.draining() && server.active_connections() == 0; }, 1s);
    require(ii::runtime::Clock::now() - start < 1s && calls == 0, "shutdown extended or dispatched incomplete request");
    require(server.listen(endpoint(), [](const auto&) { return ServerResponse{}; }), "restart after deadline");
    Tcp aborted(loop); require(bool(aborted.connect(endpoint(server.port()))), "connect before zero grace");
    until(loop, [&] { return server.active_connections() == 1; });
    require(bool(server.shutdown(0ms)) && !server.draining() && server.active_connections() == 0, "zero grace must close immediately");
}
void response_deadline() {
    ii::runtime::EventLoop loop, client_loop;
    HttpServer server(loop); ServerLimits limits; limits.response_bytes = 8 * 1024 * 1024; limits.response_timeout = 40ms;
    std::optional<ii::runtime::Clock::time_point> responding;
    require(server.listen(endpoint(), [&](const auto&) {
        responding = ii::runtime::Clock::now();
        return ServerResponse{200, {}, std::string(8 * 1024 * 1024, 'x')};
    }, limits), "response deadline listen");
    Tcp nonreader(client_loop); TcpOptions options; options.receive_buffer_bytes = 1024;
    require(bool(nonreader.connect(endpoint(server.port()), options)), "non-reader connect");
    until(loop, [&] { client_loop.poll(); return nonreader.is_connected() && server.active_connections() == 1; });
    require(nonreader.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), "non-reader request");
    until(loop, [&] { client_loop.poll(); return nonreader.pending_bytes() == 0; });
    // Stop dispatching the client loop after flushing the request. Its small
    // kernel receive window stalls the response without closing the socket.
    until(loop, [&] { return server.active_connections() == 0; }, 1s);
    require(responding && ii::runtime::Clock::now() - *responding >= limits.response_timeout,
            "response did not wait for its write deadline");
    require(nonreader.statistics().received_bytes == 0, "non-reader consumed response bytes");
    server.close();
    limits.response_timeout = 0ms;
    require(!server.listen(endpoint(), [](const auto&) { return ServerResponse{}; }, limits), "unbounded response timeout accepted");
}
}
int main(int argc, char** argv) {
    try {
        require(argc == 2, "expected test case"); const std::string test = argv[1];
        if (test == "graceful") graceful(); else if (test == "deadline") forced_deadline();
        else if (test == "response") response_deadline(); else throw std::runtime_error("unknown test");
        std::cout << "PASS http.shutdown." << test << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
