#include <iiNetwork/Realtime.h>
#include <iostream>
#include <stdexcept>

using namespace ii::network;
using namespace std::chrono_literals;
namespace
{
template<class T> T take(Result<T> value) { if (!value) throw std::runtime_error(value.error().message); return std::move(*value); }
void pass(Result<void> value) { if (!value) throw std::runtime_error(value.error().message); }
}
int main()
{
    try
    {
        ii::runtime::EventLoop loop;
        RealtimeServer hub(loop); pass(hub.listen());
        // A real application delivers these credentials over authenticated
        // Peer/TLS or trusted IPC. Their keys are never printed or broadcast.
        const auto alpha_ticket = take(hub.issue("live-session"));
        const auto beta_ticket = take(hub.issue("live-session"));
        RealtimeClient alpha(loop), beta(loop);
        unsigned alpha_frames = 0, beta_frames = 0, updates = 0;
        bool invalid = false;
        hub.received = [&](const RealtimeFrame& frame) {
            // Validate application input here, or compute an authoritative
            // snapshot and call broadcast(). This sample is an explicit relay.
            if (!hub.relay(frame)) invalid = true;
        };
        alpha.received = [&](const RealtimeFrame& frame) { if (frame.peer != beta_ticket.peer) invalid = true; ++alpha_frames; };
        beta.received = [&](const RealtimeFrame& frame) { if (frame.peer != alpha_ticket.peer) invalid = true; ++beta_frames; };
        alpha.failed = beta.failed = [&](auto) { invalid = true; loop.request_stop(); };
        const IpEndpoint address{IpAddress::loopback(), hub.port()};
        pass(alpha.connect(address, alpha_ticket)); pass(beta.connect(address, beta_ticket));
        const auto ticker = loop.every(16ms, [&] {
            if (alpha_frames >= 20 && beta_frames >= 20) { loop.request_stop(); return; }
            if (alpha.state() != RealtimeState::ready || beta.state() != RealtimeState::ready) return;
            ++updates;
            if (!alpha.publish(0, "alpha-state-" + std::to_string(updates)) ||
                !beta.publish(0, "beta-state-" + std::to_string(updates))) { invalid = true; loop.request_stop(); }
        });
        const auto deadline = loop.after(5s, [&] { invalid = true; loop.request_stop(); });
        if (!ticker || !deadline) throw std::runtime_error("Cannot schedule realtime application loop");
        loop.run(); ticker.token.cancel(); deadline.token.cancel();
        if (invalid || alpha_frames < 20 || beta_frames < 20) throw std::runtime_error("Realtime sample did not exchange live state");
        std::cout << "Native realtime room: alpha=" << alpha_frames << ", beta=" << beta_frames
                  << "; encrypted UDP state relay, same API for applications and games\n";
        alpha.close(); beta.close(); hub.close(); return 0;
    }
    catch (const std::exception& exception) { std::cerr << exception.what() << '\n'; return 1; }
}
