#include <iiNetwork/LoadBalancer.h>
#include <algorithm>
#include <mutex>

namespace ii::network {
namespace {
bool family(AddressFamily value) { return value==AddressFamily::ipv4 || value==AddressFamily::ipv6; }
void append(std::uint64_t& hash,std::uint64_t value,unsigned bytes) {
    for(unsigned i=0;i<bytes;++i) { hash^=(value>>(i*8U))&255U; hash*=1099511628211ULL; }
}
void endpoint(std::uint64_t& hash,const IpEndpoint& value) {
    append(hash,value.address.family()==AddressFamily::ipv4 ? 4U : 6U,1);
    const auto count=value.address.family()==AddressFamily::ipv4 ? 4U : 16U;
    for(unsigned i=0;i<count;++i) append(hash,value.address.bytes()[i],1);
    append(hash,value.address.scope_id(),4); append(hash,value.port,2);
}
runtime::LoadBalancerOptions routing_options(runtime::LoadBalancerOptions options) {
    options.policy=runtime::BalancePolicy::flow_hash; return options;
}
}
std::expected<std::uint64_t,runtime::SubmitError> flow_hash(const NetworkFlow& flow,std::uint64_t seed) {
    if((flow.protocol!=LoadTransport::tcp && flow.protocol!=LoadTransport::udp && flow.protocol!=LoadTransport::tls) ||
       !family(flow.source.address.family()) || !family(flow.destination.address.family()) ||
       flow.source.address.family()!=flow.destination.address.family() || !flow.destination.port ||
       (flow.protocol!=LoadTransport::udp && !flow.source.port))
        return std::unexpected(runtime::SubmitError::invalid);
    std::uint64_t hash=14695981039346656037ULL;
    append(hash,seed,8); append(hash,static_cast<std::uint64_t>(flow.protocol),1);
    endpoint(hash,flow.source); endpoint(hash,flow.destination);
    if(flow.protocol!=LoadTransport::udp) append(hash,flow.initial_sequence,4);
    return hash;
}
struct NetworkLoadBalancer::Impl final {
    struct Endpoint final { runtime::LoadTarget target; IpEndpoint address; };
    const std::uint64_t seed;
    mutable std::mutex mutex;
    std::vector<Endpoint> endpoints;
    runtime::LoadBalancer targets;
    explicit Impl(NetworkLoadBalancerOptions options)
        :seed(options.hash_seed),endpoints(options.targets.max_targets),targets(routing_options(options.targets)) {}
};
NetworkLoadBalancer::NetworkLoadBalancer(NetworkLoadBalancerOptions options):impl_(std::make_unique<Impl>(options)) {}
NetworkLoadBalancer::~NetworkLoadBalancer()=default;
std::expected<runtime::LoadTarget,runtime::SubmitError> NetworkLoadBalancer::add_target_erased(Register add,IpEndpoint backend) {
    if(!family(backend.address.family()) || !backend.port || backend.address.is_unspecified() || backend.address.is_multicast())
        return std::unexpected(runtime::SubmitError::invalid);
    std::lock_guard lock(impl_->mutex);
    if(impl_->targets.stats().stopped) return std::unexpected(runtime::SubmitError::stopped);
    const auto slot=std::find_if(impl_->endpoints.begin(),impl_->endpoints.end(),[](const auto& value){return !value.target;});
    if(slot==impl_->endpoints.end()) return std::unexpected(runtime::SubmitError::full);
    auto target=add(impl_->targets);
    if(target) *slot={*target,std::move(backend)};
    return target;
}
std::expected<NetworkRoute,runtime::SubmitError> NetworkLoadBalancer::acquire(const NetworkFlow& flow,runtime::LoadRequest resources) {
    const auto hash=flow_hash(flow,impl_->seed);
    if(!hash) return std::unexpected(hash.error());
    resources.policy=runtime::BalancePolicy::flow_hash; resources.affinity=*hash;
    std::lock_guard lock(impl_->mutex);
    auto lease=impl_->targets.acquire(resources);
    if(!lease) return std::unexpected(lease.error());
    const auto entry=std::find_if(impl_->endpoints.begin(),impl_->endpoints.end(),[&](const auto& value){return value.target==lease->target();});
    return NetworkRoute{std::move(*lease),entry->address};
}
bool NetworkLoadBalancer::report_health(runtime::LoadTarget target,bool healthy) { return impl_->targets.report_health(target,healthy); }
bool NetworkLoadBalancer::request_drain(runtime::LoadTarget target) { return impl_->targets.request_drain(target); }
runtime::ThreadResult NetworkLoadBalancer::remove_target(runtime::LoadTarget target,runtime::ShutdownMode mode) {
    const auto result=impl_->targets.remove_target(target,mode);
    if(!impl_->targets.target_stats(target)) {
        std::lock_guard lock(impl_->mutex);
        for(auto& entry:impl_->endpoints) if(entry.target==target) { entry={}; break; }
    }
    return result;
}
runtime::ThreadResult NetworkLoadBalancer::close(runtime::ShutdownMode mode) { return impl_->targets.close(mode); }
runtime::LoadBalancerStats NetworkLoadBalancer::stats() const { return impl_->targets.stats(); }
std::optional<runtime::LoadTargetStats> NetworkLoadBalancer::target_stats(runtime::LoadTarget target) const { return impl_->targets.target_stats(target); }
} // namespace ii::network
