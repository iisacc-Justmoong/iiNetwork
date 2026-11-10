#include <iiNetwork/Http.h>
#include <iiNetwork/Transport.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace {
void check(bool ok,const char* message) { if(!ok) throw std::runtime_error(message); }
}
int main() {
    try {
        ii::runtime::EventLoop loop;
        Listener listener(loop); std::unique_ptr<Tcp> accepted;
        listener.accepted=[&](auto client) { accepted=std::move(client); };
        check(listener.listen("127.0.0.1"),"HTTP test listener failed");
        Http client(loop); HttpRequest request;
        request.url="http://127.0.0.1:"+std::to_string(listener.port())+"/idle";
        request.timeout=5s; request.proxy.type=ProxyType::disabled;
        bool completed=false;
        check(bool(client.request(std::move(request),[&](auto) { completed=true; })),"HTTP request admission failed");
        const auto deadline=ii::runtime::Clock::now()+2s;
        while((!accepted || !accepted->available_bytes()) && ii::runtime::Clock::now()<deadline) {
            loop.poll(); std::this_thread::yield();
        }
        check(accepted && accepted->available_bytes(),"HTTP request did not reach the server");
        (void)accepted->read(); loop.poll();
        const auto before=loop.stats().executed;
        std::this_thread::sleep_for(70ms); loop.poll();
        check(loop.stats().executed==before && !completed,"idle HTTP transfer continued to poll");
        client.cancel();
        bool replaced=false; unsigned replacement_progress=0;
        HttpRequest replacement; replacement.url="http://127.0.0.1:"+std::to_string(listener.port())+"/replacement";
        replacement.timeout=5s; replacement.proxy.type=ProxyType::disabled;
        replacement.transfer_progress=[&](auto) { ++replacement_progress; };
        HttpRequest first; first.url="http://127.0.0.1:"+std::to_string(listener.port())+"/first";
        first.timeout=5s; first.proxy.type=ProxyType::disabled;
        first.progress=[&](auto,auto) {
            if(replaced) return;
            client.cancel(); replaced=true;
            check(bool(client.request(std::move(replacement),[](auto) {})),"replacement request was rejected");
        };
        check(bool(client.request(std::move(first),[](auto) {})),"first request was rejected");
        while(!replaced && ii::runtime::Clock::now()<deadline) {
            loop.poll({.max_callbacks=1}); std::this_thread::yield();
        }
        check(replaced,"progress callback did not replace request");
        check(replacement_progress==0,"old request drove replacement progress during reentry");
        client.cancel();
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
