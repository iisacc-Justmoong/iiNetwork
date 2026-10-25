#pragma once
#include <iiNetwork/Address.h>
#include <iiSDKCore/Runtime/LoadBalancer.h>

namespace ii::network {
enum class LoadTransport { tcp,udp,tls };
struct NetworkFlow final {
    LoadTransport protocol=LoadTransport::tcp;
    IpEndpoint source,destination;
    std::uint32_t initial_sequence=0;
};
// Canonical binary IP addresses, scope IDs, ports and protocol are hashed without
// allocation. UDP excludes initial_sequence. This is not a security primitive.
std::expected<std::uint64_t,runtime::SubmitError> flow_hash(const NetworkFlow&,std::uint64_t seed=0);
struct NetworkRoute final {
    runtime::LoadLease lease;
    IpEndpoint backend;
};
struct NetworkLoadBalancerOptions final {
    runtime::LoadBalancerOptions targets;
    std::uint64_t hash_seed=0x243f6a8885a308d3ULL;
};
// Select once when establishing a TCP/TLS connection or UDP flow. Retain the
// returned lease until transport cleanup. Packets reuse the selected backend.
class NetworkLoadBalancer final {
public:
    explicit NetworkLoadBalancer(NetworkLoadBalancerOptions={});
    ~NetworkLoadBalancer();
    NetworkLoadBalancer(const NetworkLoadBalancer&)=delete;
    NetworkLoadBalancer& operator=(const NetworkLoadBalancer&)=delete;
    template<runtime::TaskExecutor Executor>
    std::expected<runtime::LoadTarget,runtime::SubmitError> add_target(
        Executor& executor,IpEndpoint backend,runtime::LoadTargetOptions options={}) {
        return add_target_erased([&executor,options=std::move(options)](runtime::LoadBalancer& targets) mutable {
            return targets.add_target(executor,std::move(options));
        },std::move(backend));
    }
    std::expected<NetworkRoute,runtime::SubmitError> acquire(const NetworkFlow&,runtime::LoadRequest={});
    bool report_health(runtime::LoadTarget,bool);
    bool request_drain(runtime::LoadTarget);
    runtime::ThreadResult remove_target(runtime::LoadTarget,runtime::ShutdownMode=runtime::ShutdownMode::cancel_pending);
    runtime::ThreadResult close(runtime::ShutdownMode=runtime::ShutdownMode::cancel_pending);
    runtime::LoadBalancerStats stats() const;
    std::optional<runtime::LoadTargetStats> target_stats(runtime::LoadTarget) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    using Register=std::function<std::expected<runtime::LoadTarget,runtime::SubmitError>(runtime::LoadBalancer&)>;
    std::expected<runtime::LoadTarget,runtime::SubmitError> add_target_erased(Register,IpEndpoint);
};
} // namespace ii::network
