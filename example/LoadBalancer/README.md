# iiNetwork load-balancer composition

This separately configured application adapter combines iiNetwork addresses with
iiSDKCore's runtime load-balancer. It is not part of the iiNetwork library.
Build this project against independently installed SDK packages, then use
`find_package(iiNetworkLoadBalancer CONFIG REQUIRED)` and link
`iiNetwork::LoadBalancer` in a consuming application. See
[the load-balancer contract](../../docs/LoadBalancer.md) for behavior and migration.
