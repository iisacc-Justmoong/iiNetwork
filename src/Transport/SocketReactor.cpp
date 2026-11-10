#include "SocketReactor.h"
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace ii::network::detail {
struct SocketWatchState final {
    native::Handle fd=native::invalid;
    runtime::EventLoop::Sender sender;
    runtime::TaskToken token;
    SocketWatch::Callback callback;
    short desired=0,events=0;
    std::uint64_t id=0,version=0;
    std::size_t in_flight=0;
    bool armed=false,pending=false,removed=false;
};
namespace {
#if defined(_WIN32)
using PollDescriptor=WSAPOLLFD;
constexpr short input_event=POLLRDNORM,output_event=POLLWRNORM;
#else
using PollDescriptor=pollfd;
constexpr short input_event=POLLIN,output_event=POLLOUT;
#endif
class SocketReactor final {
public:
    static SocketReactor& instance() { static SocketReactor reactor; return reactor; }
    SocketReactor() {
        native::initialize();
#if defined(_WIN32)
        read_=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(read_==native::invalid) throw std::runtime_error("socket reactor wake receiver failed");
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        native::Length length=sizeof(address);
        if(::bind(read_,reinterpret_cast<sockaddr*>(&address),sizeof(address)) ||
           getsockname(read_,reinterpret_cast<sockaddr*>(&address),&length)) {
            native::close(read_); throw std::runtime_error("socket reactor wake bind failed");
        }
        write_=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(write_==native::invalid || ::connect(write_,reinterpret_cast<sockaddr*>(&address),sizeof(address))) {
            native::close(read_); native::close(write_); throw std::runtime_error("socket reactor wake sender failed");
        }
#else
        int handles[2];
        if(::socketpair(AF_UNIX,SOCK_STREAM,0,handles)) throw std::runtime_error("socket reactor wake pair failed");
        read_=handles[0]; write_=handles[1];
#endif
        if(!native::options(read_) || !native::options(write_)) {
            native::close(read_); native::close(write_); throw std::runtime_error("socket reactor wake setup failed");
        }
        try { worker_=std::thread([this] { run(); }); }
        catch (...) { native::close(read_); native::close(write_); throw; }
    }
    ~SocketReactor() {
        { std::lock_guard lock(mutex_); stopping_=true; }
        wake();
        if(worker_.joinable()) worker_.join();
        native::close(read_); native::close(write_);
    }
    bool add(const std::shared_ptr<SocketWatchState>& state) {
        std::lock_guard lock(mutex_);
        if(stopping_ || entries_.size()>=4096 || next_==0) return false;
        state->id=next_++;
        entries_.emplace(state->id,state);
        wake(); return true;
    }
    bool interest(const std::shared_ptr<SocketWatchState>& state,short desired) {
        std::lock_guard lock(mutex_);
        if(state->removed || stopping_) return false;
        if(state->desired==desired && (state->pending || state->armed==(desired!=0))) return true;
        state->desired=desired; ++state->version;
        state->armed=!state->pending && desired!=0;
        wake(); return true;
    }
    short take(const std::shared_ptr<SocketWatchState>& state) {
        std::lock_guard lock(mutex_); return std::exchange(state->events,short{});
    }
    void complete(const std::shared_ptr<SocketWatchState>& state) {
        std::lock_guard lock(mutex_);
        if(state->removed || stopping_) return;
        state->pending=false; state->armed=state->desired!=0; ++state->version; wake();
    }
    void remove(const std::shared_ptr<SocketWatchState>& state) {
        std::unique_lock lock(mutex_);
        if(!state->removed) {
            state->removed=true; state->armed=false; ++state->version;
            entries_.erase(state->id); wake();
        }
        retired_.wait(lock,[&] { return state->in_flight==0; });
    }
#ifdef IINETWORK_TESTING
    void fail_for_test() { failure_requested_.store(true,std::memory_order_release); wake(); }
#endif
private:
    struct Snapshot { std::shared_ptr<SocketWatchState> state; std::uint64_t version; };
    void wake() noexcept {
        const char value=1;
        int result;
        do {
            result=static_cast<int>(::send(write_,&value,1,native::send_flags()));
#if defined(_WIN32)
        } while(result<0 && WSAGetLastError()==WSAEINTR);
#else
        } while(result<0 && errno==EINTR);
#endif
    }
    void drain() noexcept {
        char bytes[128];
        while(::recv(read_,bytes,sizeof(bytes),0)>0) {}
    }
    void run() noexcept {
        std::vector<Snapshot> snapshot;
        std::vector<PollDescriptor> descriptors;
        std::vector<std::shared_ptr<SocketWatchState>> notify;
        try {
            for(;;) {
#ifdef IINETWORK_TESTING
                if(failure_requested_.exchange(false,std::memory_order_acq_rel)) throw std::bad_alloc{};
#endif
                descriptors.clear(); snapshot.clear(); notify.clear();
                {
                    std::lock_guard lock(mutex_);
                    if(stopping_) return;
                    descriptors.push_back({read_,input_event,0});
                    for(const auto& [id,state]:entries_) {
                        (void)id;
                        if(!state->armed || state->removed) continue;
                        descriptors.push_back({state->fd,state->desired,0});
                        snapshot.push_back({state,state->version}); ++state->in_flight;
                    }
                }
#if defined(_WIN32)
                const int result=::WSAPoll(descriptors.data(),static_cast<ULONG>(descriptors.size()),-1);
                const bool interrupted=result<0 && WSAGetLastError()==WSAEINTR;
#else
                const int result=::poll(descriptors.data(),static_cast<nfds_t>(descriptors.size()),-1);
                const bool interrupted=result<0 && errno==EINTR;
#endif
                if(result>0 && descriptors.front().revents) drain();
                {
                    std::lock_guard lock(mutex_);
                    for(std::size_t i=0;i<snapshot.size();++i) {
                        auto& item=snapshot[i]; auto& state=*item.state;
                        const short events=(result<0 && !interrupted) ? POLLERR : descriptors[i+1].revents;
                        if(events && !state.removed && state.armed && state.version==item.version) {
                            state.armed=false; state.pending=true; state.events|=events;
                            notify.push_back(item.state);
                        }
                        --state.in_flight;
                        item.state.reset();
                    }
                    retired_.notify_all();
                }
                for(const auto& state:notify)
                    if(!state->sender.signal(state->token,runtime::Clock::now())) {
                        std::lock_guard lock(mutex_); state->removed=true; state->armed=false; entries_.erase(state->id);
                    }
            }
        } catch (...) {
            // Moving the registrations does not allocate, even when the
            // original error was allocation failure. Signal outside the lock:
            // a host wake may interact with a cancelling owner.
            std::map<std::uint64_t,std::shared_ptr<SocketWatchState>> failed;
            {
                std::lock_guard lock(mutex_);
                stopping_=true;
                for(auto& item:snapshot) if(item.state && item.state->in_flight) --item.state->in_flight;
                for(auto& [id,state]:entries_) {
                    (void)id; state->removed=true; state->armed=false; state->pending=true;
                    state->events|=static_cast<short>(POLLERR|POLLNVAL);
                }
                failed.swap(entries_); retired_.notify_all();
            }
            for(const auto& [id,state]:failed) {
                (void)id;
                try { (void)state->sender.signal(state->token,runtime::Clock::now()); }
                catch (...) { /* The owner loop may itself already be unavailable. */ }
            }
        }
    }
    std::mutex mutex_;
    std::condition_variable retired_;
    std::map<std::uint64_t,std::shared_ptr<SocketWatchState>> entries_;
    native::Handle read_=native::invalid,write_=native::invalid;
    std::thread worker_;
    std::uint64_t next_=1;
    bool stopping_=false;
#ifdef IINETWORK_TESTING
    std::atomic_bool failure_requested_{false};
#endif
};
}
std::unique_ptr<SocketWatch> SocketWatch::create(runtime::EventLoop& loop,native::Handle fd,Callback callback) {
    if(fd==native::invalid || !callback) return {};
    std::shared_ptr<SocketWatchState> state;
    bool registered=false;
    try {
        state=std::make_shared<SocketWatchState>(); state->fd=fd; state->sender=loop.sender(); state->callback=std::move(callback);
        const std::weak_ptr<SocketWatchState> weak=state;
        auto submitted=state->sender.on_signal([weak] {
            auto keep=weak.lock(); if(!keep) return;
            auto& reactor=SocketReactor::instance(); const auto events=reactor.take(keep);
            try { keep->callback(events); }
            catch (...) { reactor.remove(keep); throw; }
            reactor.complete(keep);
        });
        if(!submitted) return {};
        state->token=submitted.token;
        if(!SocketReactor::instance().add(state)) { state->token.cancel(); return {}; }
        registered=true;
        return std::unique_ptr<SocketWatch>(new SocketWatch(std::move(state)));
    } catch (...) {
        if(state) { if(registered) SocketReactor::instance().remove(state); state->token.cancel(); }
        return {};
    }
}
SocketWatch::~SocketWatch() { cancel(); }
bool SocketWatch::set_interest(bool readable,bool writable) {
    if(!state_) return false;
    return SocketReactor::instance().interest(state_,static_cast<short>((readable?input_event:0)|(writable?output_event:0)));
}
bool SocketWatch::kick() { return state_ && state_->sender.signal(state_->token,runtime::Clock::now()); }
void SocketWatch::cancel() {
    if(!state_) return;
    auto state=std::move(state_); SocketReactor::instance().remove(state); state->token.cancel();
}
#ifdef IINETWORK_TESTING
void SocketWatch::fail_reactor_for_test() { SocketReactor::instance().fail_for_test(); }
#endif
}
