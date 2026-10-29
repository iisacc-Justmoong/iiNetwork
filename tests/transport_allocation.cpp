#include <iiNetwork/Network.h>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
using namespace std::chrono_literals;
namespace injection { thread_local bool fail=false; }
void* operator new(std::size_t n) {
    if(injection::fail) { injection::fail=false; throw std::bad_alloc(); }
    if(auto* p=std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void operator delete[](void* p,std::size_t) noexcept { std::free(p); }
namespace {
void check(bool ok,const char* message) { if(!ok) throw std::runtime_error(message); }
template<class F> bool wait(ii::runtime::EventLoop& loop,F predicate) {
    const auto end=ii::runtime::Clock::now()+5s;
    while(!predicate() && ii::runtime::Clock::now()<end) { loop.poll(); std::this_thread::sleep_for(1ms); }
    return predicate();
}
void run(const std::string& mode) {
    ii::runtime::EventLoop loop; ii::network::Listener listener(loop); std::unique_ptr<ii::network::Tcp> peer;
    listener.accepted=[&](auto value) { peer=std::move(value); };
    check(listener.listen(),"listener failed"); ii::network::Tcp socket(loop);
    check(socket.connect("127.0.0.1",listener.port()),"connect rejected");
    check(wait(loop,[&] { return socket.is_connected() && bool(peer); }),"loopback connection failed");
    std::string received;
    peer->readable=[&] { received+=peer->read(); };
    const auto before=socket.pending_bytes();
    if(mode=="view") {
        bool threw=false, accepted=false;
        injection::fail=true;
        try { accepted=socket.write(std::string_view("abc")); } catch(const std::bad_alloc&) { threw=true; }
        injection::fail=false;
        if(threw) { std::cerr << "WRITE_ALLOCATION_THREW view\n"; throw std::runtime_error("write leaked allocation failure"); }
        check(!accepted && socket.pending_bytes()==before,"failed view write changed pending bytes");
        check(socket.write(std::string_view("abc")),"subsequent view write failed");
        check(wait(loop,[&] { return socket.pending_bytes()==0 && received=="abc"; }),
              "view write did not drain after allocation failure");
    } else {
        auto payload=std::make_shared<const std::string>("x");
        std::size_t failures=0, successful=0; bool failedWithQueuedData=false;
        for(std::size_t i=0;i<512 && failures<2;++i) {
            const auto previous=socket.pending_bytes(); bool threw=false, accepted=false;
            injection::fail=true;
            try { accepted=socket.write(payload); } catch(const std::bad_alloc&) { threw=true; }
            const bool fired=!injection::fail; injection::fail=false;
            if(fired) {
                ++failures; failedWithQueuedData|=previous>0;
                if(socket.pending_bytes()!=previous) {
                    std::cerr << "QUEUE_COUNTER_CORRUPT before=" << previous << " after=" << socket.pending_bytes() << " iteration=" << i << '\n';
                    throw std::runtime_error("failed enqueue changed queue accounting");
                }
                if(threw) { std::cerr << "WRITE_ALLOCATION_THREW shared\n"; throw std::runtime_error("write leaked allocation failure"); }
                check(!accepted,"failed allocation was accepted");
                check(socket.write(payload),"subsequent shared write failed"); ++successful;
                continue;
            }
            check(!threw && accepted && socket.pending_bytes()==previous+payload->size(),"successful enqueue accounting differs");
            ++successful;
        }
        check(failures==2 && failedWithQueuedData && successful>0,"did not inject failure with an existing queue");
        check(wait(loop,[&] { return socket.pending_bytes()==0 && received.size()==successful; }),
              "queued bytes did not drain after allocation failures");
        check(received==std::string(successful,'x'),"queued payloads changed");
        std::cout << "NETWORK_ALLOCATION_COUNTS failures=" << failures << " successful=" << successful << '\n';
    }
    socket.close(); listener.close();
    std::cout << "NETWORK_ALLOCATION_OK " << mode << '\n';
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"expected shared or view case"); const std::string mode=argv[1];
          check(mode=="shared" || mode=="view","unknown case"); run(mode); }
    catch(const std::exception& error) { injection::fail=false; std::cerr << error.what() << '\n'; return 1; }
}
