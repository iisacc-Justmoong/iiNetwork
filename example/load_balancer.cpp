#include <iiNetwork/LoadBalancer.h>
#include <iiNetwork/Transport.h>
#include <chrono>
#include <iostream>
#include <thread>

int main() {
    using namespace ii::network;
    using namespace ii::runtime;
    using namespace std::chrono_literals;
    EventLoop loop;
    Listener backend(loop);
    std::unique_ptr<Tcp> accepted;
    backend.accepted=[&](auto stream){accepted=std::move(stream);};
    if(!backend.listen(IpEndpoint{IpAddress::loopback(),0})) return 1;
    NetworkLoadBalancer balance;
    if(!balance.add_target(loop,{IpAddress::loopback(),backend.port()},{.name="native-backend",.capacity=8})) return 2;
    NetworkFlow flow{.source={IpAddress::loopback(),43000},.destination={IpAddress::loopback(),443},.initial_sequence=1};
    auto route=balance.acquire(flow);
    if(!route) return 3;
    Tcp upstream(loop);
    if(!upstream.connect(route->backend)) return 4;
    const auto deadline=Clock::now()+5s;
    while((!accepted || !upstream.is_connected()) && Clock::now()<deadline) { loop.poll(); std::this_thread::sleep_for(1ms); }
    if(!accepted || !upstream.is_connected() || !upstream.write("horizontal")) return 5;
    while(!accepted->available_bytes() && Clock::now()<deadline) { loop.poll(); std::this_thread::sleep_for(1ms); }
    const auto payload=accepted->read();
    upstream.close(); accepted.reset();
    route->lease.complete();
    if(!balance.close(ShutdownMode::drain) || payload!="horizontal") return 6;
    std::cout<<"Network load balancing complete: payload="<<payload<<'\n';
}
