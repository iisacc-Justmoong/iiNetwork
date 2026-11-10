#pragma once
#include "SocketInternal.h"
#include <functional>
#include <memory>

namespace ii::network::detail {
struct SocketWatchState;
// One bounded owner-loop slot and one shared native readiness registration.
class SocketWatch final {
public:
    using Callback=std::function<void(short)>;
    static std::unique_ptr<SocketWatch> create(runtime::EventLoop&,native::Handle,Callback);
    ~SocketWatch();
    SocketWatch(const SocketWatch&)=delete;
    SocketWatch& operator=(const SocketWatch&)=delete;
    bool set_interest(bool readable,bool writable);
    bool kick();
    void cancel();
#ifdef IINETWORK_TESTING
    // Test-only, process-wide fault injection. The failed reactor cannot restart.
    static void fail_reactor_for_test();
#endif
private:
    explicit SocketWatch(std::shared_ptr<SocketWatchState> state):state_(std::move(state)) {}
    std::shared_ptr<SocketWatchState> state_;
};
}
