#include "../src/Transport/SocketReactor.h"
#include <iiNetwork/Realtime.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace {
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
}
int main() {
    try {
#ifndef _WIN32
        int sockets[2]; check(::socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0,"socket pair failed");
        struct Close final { int* sockets; ~Close() { native::close(sockets[0]); native::close(sockets[1]); } } close{sockets};
        check(native::options(sockets[0]) && native::options(sockets[1]),"nonblocking setup failed");
        ii::runtime::EventLoop loop;
        unsigned calls=0;
        auto watch=detail::SocketWatch::create(loop,sockets[0],[&](short) {
            char byte=0; check(::recv(sockets[0],&byte,1,0)==1,"readiness had no data"); ++calls;
        });
        check(bool(watch) && watch->set_interest(true,false),"readiness watch rejected");
        std::this_thread::sleep_for(70ms);
        check(loop.poll()==0,"idle socket caused periodic dispatch");
        check(::send(sockets[1],"a",1,0)==1,"send failed");
        const auto deadline=ii::runtime::Clock::now()+2s;
        while(calls<1 && ii::runtime::Clock::now()<deadline) { loop.poll(); std::this_thread::yield(); }
        check(calls==1,"readiness was not delivered");
        std::this_thread::sleep_for(40ms); loop.poll();
        check(calls==1,"readiness was repeatedly delivered without data");
        check(::send(sockets[1],"b",1,0)==1,"second send failed");
        while(calls<2 && ii::runtime::Clock::now()<deadline) { loop.poll(); std::this_thread::yield(); }
        check(calls==2,"watch did not rearm after the first event");
        watch.reset();
        check(::send(sockets[1],"c",1,0)==1,"send after cancellation failed");
        std::this_thread::sleep_for(20ms); loop.poll();
        check(calls==2,"cancelled watch delivered a callback");
        ii::runtime::EventLoop transport_loop;
        Listener listener(transport_loop); std::unique_ptr<Tcp> accepted;
        listener.accepted=[&](auto client) { accepted=std::move(client); };
        check(listener.listen(),"listener creation failed");
        Tcp client(transport_loop); check(client.connect("127.0.0.1",listener.port()),"client connection failed");
        const auto connected_by=ii::runtime::Clock::now()+2s;
        while((!accepted || !client.is_connected()) && ii::runtime::Clock::now()<connected_by) {
            transport_loop.poll(); std::this_thread::yield();
        }
        check(accepted && client.is_connected(),"transport readiness was not delivered");
        transport_loop.poll(); const auto idle=transport_loop.stats().executed;
        std::this_thread::sleep_for(50ms); transport_loop.poll();
        check(transport_loop.stats().executed==idle,"idle TCP or listener continued to poll");
        ii::runtime::EventLoop realtime_loop;
        RealtimeServer realtime(realtime_loop);
        check(bool(realtime.listen()),"realtime listener failed");
        realtime_loop.poll(); const auto realtime_idle=realtime_loop.stats().executed;
        std::this_thread::sleep_for(40ms); realtime_loop.poll();
        check(realtime_loop.stats().executed==realtime_idle,"idle realtime listener continued to poll");
        check(bool(realtime.issue("room",60ms)),"ticket admission failed");
        std::this_thread::sleep_for(80ms); realtime_loop.poll();
        check(realtime.pending_tickets()==0,"ticket expiration was not scheduled");
#endif
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
