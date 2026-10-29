cmake_minimum_required(VERSION 3.24)
# iisdk:consumer-application
project(iiNetworkInstalledLoadBalancer LANGUAGES CXX)
include(CTest)
find_package(iiNetworkLoadBalancer 0.6 CONFIG REQUIRED)
add_executable(iiNetworkInstalledLoadBalancer ../load_balancer.cpp)
target_link_libraries(iiNetworkInstalledLoadBalancer PRIVATE iiNetwork::LoadBalancer)
add_test(NAME iiNetwork.Installed.LoadBalancer COMMAND iiNetworkInstalledLoadBalancer)
set_tests_properties(iiNetwork.Installed.LoadBalancer PROPERTIES TIMEOUT 30)
