#include "../src/Transport/SocketReactor.h"
#include <iiNetwork/Transport.h>
#include <iiNetwork/Tls.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}
int main(int argc, char** argv) {
    try {
        check(argc == 2, "TLS fixture directory missing");
        ii::runtime::EventLoop loop;
        Listener listener(loop);
        Udp datagrams(loop);
        TlsOptions options;
        options.policy.identity.certificate_chain_file = std::string(argv[1]) + "/server.pem";
        options.policy.identity.private_key_file = std::string(argv[1]) + "/server.key";
        auto context = TlsContext::server(std::move(options));
        check(bool(context), "TLS context setup failed");
        TlsListener secure(loop, *context);
        int listener_failures = 0, udp_failures = 0, tcp_failures = 0, cancelled_failures = 0, tls_failures = 0;
        listener.on_failure([&](std::string message) { if (!message.empty()) ++listener_failures; });
        datagrams.failed = [&](std::string message) { if (!message.empty()) ++udp_failures; };
        secure.failed = [&](std::string message) { if (!message.empty()) ++tls_failures; };
        check(listener.listen("127.0.0.1", 0), "listener setup failed");
        check(datagrams.bind("127.0.0.1", 0), "UDP setup failed");
        check(bool(secure.listen({*IpAddress::parse("127.0.0.1"), 0})), "TLS listener setup failed");
        Listener cancelled(loop);
        cancelled.on_failure([&](std::string) { ++cancelled_failures; });
        check(cancelled.listen("127.0.0.1", 0), "cancelled listener setup failed");
        cancelled.close();
        std::unique_ptr<Tcp> accepted;
        listener.accepted = [&](std::unique_ptr<Tcp> stream) { accepted = std::move(stream); };
        Tcp client(loop);
        client.failed = [&](std::string message) { if (!message.empty()) ++tcp_failures; };
        check(client.connect("127.0.0.1", listener.port()), "TCP connection setup failed");
        const auto connected_by = ii::runtime::Clock::now() + 2s;
        while ((!accepted || !client.is_connected()) && ii::runtime::Clock::now() < connected_by) {
            loop.poll(); std::this_thread::yield();
        }
        check(accepted && client.is_connected(), "TCP connection was not established");
        detail::SocketWatch::fail_reactor_for_test();
        const auto deadline = ii::runtime::Clock::now() + 2s;
        while ((listener_failures != 1 || udp_failures != 1 || tcp_failures != 1 || tls_failures != 1) && ii::runtime::Clock::now() < deadline) {
            loop.poll();
            std::this_thread::yield();
        }
        check(listener_failures == 1, "listener did not receive the reactor failure");
        check(udp_failures == 1, "UDP did not receive the reactor failure");
        check(tcp_failures == 1 && client.state() == SocketState::failed, "TCP did not fail on reactor failure");
        check(tls_failures == 1 && !secure.error().empty(), "TLS listener did not receive the reactor failure");
        check(cancelled_failures == 0, "cancelled listener received a late failure");
        check(!listener.error().empty() && !datagrams.error().empty(), "failure state was not retained");
        loop.poll();
        check(listener_failures == 1 && udp_failures == 1 && tcp_failures == 1 && tls_failures == 1, "failure was delivered more than once");
        Listener rejected(loop);
        check(!rejected.listen("127.0.0.1", 0), "failed reactor accepted a new registration");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
