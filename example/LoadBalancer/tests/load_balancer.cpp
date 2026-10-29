#include <iiNetwork/LoadBalancer.h>
#include <iiNetwork/Transport.h>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace ii::network;
using namespace ii::runtime;
using namespace std::chrono_literals;
namespace {
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
IpEndpoint endpoint(std::uint16_t port,AddressFamily family=AddressFamily::ipv4) { return {IpAddress::loopback(family),port}; }
NetworkFlow flow(std::uint16_t port=12345,LoadTransport protocol=LoadTransport::tcp) {
    return {.protocol=protocol,.source=endpoint(port),.destination=endpoint(443),.initial_sequence=123};
}
template<class Done> void until(EventLoop& loop,Done done) {
    const auto deadline=Clock::now()+5s;
    while(!done() && Clock::now()<deadline) { loop.poll(); std::this_thread::sleep_for(1ms); }
    check(done(),"loopback traffic timed out");
}
void keys_and_bounds() {
    auto key=flow();
    const auto original=flow_hash(key,42).value();
    ++key.initial_sequence;
    check(flow_hash(key,42).value()!=original,"TCP sequence participates in connection identity");
    key.protocol=LoadTransport::udp;
    const auto datagram=flow_hash(key,42).value(); ++key.initial_sequence;
    check(flow_hash(key,42).value()==datagram,"UDP flow ignores TCP sequence");
    ++key.source.port;
    check(flow_hash(key,42).value()!=datagram,"source port participates in flow identity");
    key.source=endpoint(12345,AddressFamily::ipv6); key.destination=endpoint(443,AddressFamily::ipv6);
    check(bool(flow_hash(key,42)),"IPv6 flow key supported");
    key.protocol=static_cast<LoadTransport>(99);
    check(flow_hash(key,42).error()==SubmitError::invalid,"invalid transport rejected");
    EventLoop loop;
    NetworkLoadBalancer balance({.targets={.max_targets=1}});
    check(!balance.add_target(loop,endpoint(0)),"backend requires an actual port");
    check(bool(balance.add_target(loop,endpoint(8000))),"valid backend admitted");
    check(balance.add_target(loop,endpoint(8001)).error()==SubmitError::full,"backend table bounded");
    check(bool(balance.close()) && balance.add_target(loop,endpoint(8002)).error()==SubmitError::stopped,
          "closed routing table rejects registration as stopped");
}
void consistent_horizontal_distribution() {
    EventLoop a,b,c;
    NetworkLoadBalancer balance({.targets={.max_targets=3,.capacity=64},.hash_seed=42});
    const auto first=balance.add_target(a,endpoint(8001),{.capacity=64}).value();
    const auto second=balance.add_target(b,endpoint(8002),{.capacity=64}).value();
    std::vector<LoadTarget> before;
    std::size_t first_count=0,second_count=0;
    for(std::uint16_t i=1000;i<2024;++i) {
        auto route=balance.acquire(flow(i)).value();
        before.push_back(route.lease.target());
        if(route.lease.target()==first) ++first_count; else ++second_count;
        check(route.backend.port==(route.lease.target()==first ? 8001 : 8002),"backend and reservation are selected atomically");
        route.lease.complete();
    }
    check(first_count>400 && second_count>400,"distinct connections spread horizontally");
    auto active=balance.acquire(flow(1000)).value();
    const auto pinned=active.lease.target();
    const auto third=balance.add_target(c,endpoint(8003),{.capacity=64}).value();
    std::size_t remapped=0;
    for(std::uint16_t i=1000;i<2024;++i) {
        auto route=balance.acquire(flow(i)).value();
        if(route.lease.target()!=before[static_cast<std::size_t>(i-1000)]) {
            check(route.lease.target()==third,"adding a target only remaps winning flows to that target"); ++remapped;
        }
        route.lease.complete();
    }
    check(remapped>200 && remapped<450,"new target receives a bounded share of new connections");
    check(balance.request_drain(pinned) && active.lease.target()==pinned,"existing connection stays pinned during topology changes");
    for(int i=0;i<8;++i) {
        auto next=balance.acquire(flow(static_cast<std::uint16_t>(3000+i))).value();
        check(next.lease.target()!=pinned,"new connections exclude draining target"); next.lease.complete();
    }
    active.lease.complete();
    check(bool(balance.remove_target(pinned,ShutdownMode::drain)),"drained backend removal");
    check(!balance.target_stats(pinned),"removed backend metadata retired");
    std::cout<<"L4 rendezvous distribution: "<<first_count<<'/'<<second_count<<"; remapped_to_new="<<remapped<<"/1024\n";
    (void)second;
}
void weighted_and_health() {
    EventLoop a,b;
    NetworkLoadBalancer balance;
    const auto first=balance.add_target(a,endpoint(8001),{.capacity=1,.unhealthy_threshold=1}).value();
    const auto second=balance.add_target(b,endpoint(8002),{.capacity=3,.unhealthy_threshold=1}).value();
    int small=0,large=0;
    for(std::uint16_t i=1000;i<2024;++i) {
        auto route=balance.acquire(flow(i)).value();
        route.lease.target()==first ? ++small : ++large; route.lease.complete();
    }
    check(large>small*2 && large<small*4,"weighted rendezvous reflects unequal target capacity");
    check(balance.report_health(first,false) && balance.report_health(second,false),"both backends marked unhealthy");
    check(balance.acquire(flow()).error()==SubmitError::overloaded,"unhealthy targets never receive new connections");
    check(balance.report_health(first,true) && balance.report_health(first,true),"health recovery");
    auto route=balance.acquire(flow()).value();
    check(route.lease.target()==first,"recovered target used");
    const auto closing=balance.close();
    check(!closing && closing.error().code==ThreadErrorCode::would_block && route.lease.stop_token().stop_requested(),
          "active transport owner is asked to close before quota returns");
    route.lease.cancel(); check(bool(balance.close()),"final close after transport retirement");
}
void real_tcp_and_udp() {
    EventLoop loop;
    Listener first(loop),second(loop);
    std::vector<std::unique_ptr<Tcp>> accepted;
    first.accepted=[&](auto socket){accepted.push_back(std::move(socket));};
    second.accepted=first.accepted;
    check(bool(first.listen(endpoint(0))) && bool(second.listen(endpoint(0))),"real backend listeners start");
    NetworkLoadBalancer balance;
    (void)balance.add_target(loop,endpoint(first.port()),{.capacity=8}).value();
    (void)balance.add_target(loop,endpoint(second.port()),{.capacity=8}).value();
    auto route=balance.acquire(flow()).value();
    Tcp upstream(loop);
    check(bool(upstream.connect(route.backend)),"connect to selected actual backend");
    until(loop,[&]{return upstream.is_connected() && accepted.size()==1;});
    check(upstream.peer_endpoint()==std::optional(route.backend),"real connection reaches selected endpoint");
    check(upstream.write("first"),"first payload");
    until(loop,[&]{return accepted.front()->available_bytes()==5;});
    check(accepted.front()->read()=="first","selected backend receives payload");
    const auto pinned=route.lease.target();
    check(balance.request_drain(pinned) && upstream.write("second"),"active TCP connection survives target drain");
    until(loop,[&]{return accepted.front()->available_bytes()==6;});
    check(accepted.front()->read()=="second" && route.lease.target()==pinned,"subsequent bytes remain on the same connection");
    upstream.close(); accepted.clear(); route.lease.complete();
    check(bool(balance.remove_target(pinned,ShutdownMode::drain)),"TCP backend removed after stream closure");

    Udp sender(loop),receiver(loop);
    check(bool(sender.bind(endpoint(0))) && bool(receiver.bind(endpoint(0))),"real UDP endpoints bind");
    NetworkLoadBalancer datagrams;
    (void)datagrams.add_target(loop,endpoint(receiver.port()),{.capacity=8}).value();
    auto udp_flow=flow(sender.port(),LoadTransport::udp);
    auto udp=datagrams.acquire(udp_flow).value();
    std::vector<std::string> packets;
    receiver.received=[&](Datagram packet){packets.push_back(std::move(packet.bytes));};
    check(bool(sender.send("one",udp.backend)) && bool(sender.send("two",udp.backend)),"route UDP packets to selected backend");
    until(loop,[&]{return packets.size()==2;});
    check(packets[0]=="one" && packets[1]=="two","real datagrams retain the selected flow destination");
    sender.close(); receiver.close(); udp.lease.complete();
}
void concurrent_selection() {
    EventLoop executor;
    NetworkLoadBalancer balance;
    (void)balance.add_target(executor,endpoint(8001),{.capacity=32}).value();
    (void)balance.add_target(executor,endpoint(8002),{.capacity=32}).value();
    std::atomic<bool> failed=false;
    std::array<std::thread,4> producers;
    for(std::size_t thread=0;thread<producers.size();++thread) producers[thread]=std::thread([&,thread] {
        for(std::uint16_t i=1000;i<1500;++i) {
            auto route=balance.acquire(flow(static_cast<std::uint16_t>(i+thread*1000)));
            if(!route || (route->backend.port!=8001 && route->backend.port!=8002)) failed=true;
            if(route) route->lease.complete();
        }
    });
    for(auto& producer:producers) producer.join();
    check(!failed && balance.stats().completed==2000 && balance.stats().in_flight==0,
          "concurrent selectors retain matching endpoint and reservation accounting");
}
}
int main() {
    try {
        keys_and_bounds(); consistent_horizontal_distribution(); weighted_and_health(); real_tcp_and_udp(); concurrent_selection();
        std::cout<<"native Network load balancing contracts passed\n";
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
