#include <iiNetwork/Peer.h>
#include <iostream>
#include <thread>

int main()
{
    using namespace ii::network;
    using Value = ii::core::Value;
    using namespace std::chrono_literals;
    ii::runtime::EventLoop loop;
    Peer alpha(loop, "alpha"), beta(loop, "beta");
    std::int64_t alpha_counter = 0, beta_counter = 0;
    auto counter = [](std::int64_t& state) -> Peer::Handler
    {
        return [&state](PeerCall call, PeerReply reply)
        {
            auto number = call.arguments.get<std::int64_t>();
            if (!number) { (void)reply(std::unexpected(Error{ErrorCode::invalid_argument, Layer::application, "Expected integer"})); return; }
            state += number->get(); (void)reply(Value(state));
        };
    };
    if (!alpha.expose("counter.add", counter(alpha_counter)) || !beta.expose("counter.add", counter(beta_counter)) ||
        !beta.listen({IpAddress::loopback(), 0})) return 1;
    bool failed = false; unsigned replies = 0;
    auto complete = [&](Result<Value> result) { if (result) ++replies; else failed = true; };
    // The accepting node initiates an operation on the dialing node.
    beta.connected = [&](auto link) { if (!link->request("counter.add", Value(11), complete)) failed = true; };
    auto link = alpha.connect({IpAddress::loopback(), beta.port()});
    if (!link) return 2;
    // The dialing node uses the exact same operation API in the other direction.
    (*link)->connected = [&] { if (!(*link)->request("counter.add", Value(7), complete)) failed = true; };
    auto deadline = ii::runtime::Clock::now() + 5s;
    while (!failed && replies < 2 && ii::runtime::Clock::now() < deadline)
    { loop.poll(); std::this_thread::sleep_for(1ms); }
    if (failed || replies != 2 || alpha_counter != 11 || beta_counter != 7) return 3;
    std::cout << "Equal peers over one connection: alpha=" << alpha_counter << ", beta=" << beta_counter << '\n';
}
