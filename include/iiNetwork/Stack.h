#pragma once
#include <iiNetwork/Layers.h>
#include <iiNetwork/Session.h>
#include <iiNetwork/Presentation.h>
#include <iiNetwork/Application.h>
#include <iiNetwork/Relay.h>
#include <iiNetwork/Server.h>

namespace ii::network
{
struct StackEndpoint final
{
    MacAddress mac;
    Ipv4Address ip;
    std::uint16_t port = 0;
};
struct StackPeer final
{
    Ipv4Address ip;
    std::uint16_t port = 0;
    MacAddress next_hop_mac; // explicit neighbor resolution; gateway MAC when routed
    [[nodiscard]] std::string identity() const;
};
struct ReceivedMessage final { SessionId session; StackPeer peer; core::Value value; };
// Seven composable objects, with a bounded authenticated Ethernet/IPv4/UDP pipeline.
// Native TCP/HTTP use the OS network stack through transport/application instead.
class NetworkStack final
{
  public:
    NetworkStack(runtime::EventLoop&, StackEndpoint, std::shared_ptr<PhysicalMedium> = {});
    NetworkStack(const NetworkStack&) = delete;
    NetworkStack& operator=(const NetworkStack&) = delete;
    PhysicalLayer physical;
    DataLinkLayer data_link;
    NetworkLayer network;
    TransportLayer transport;
    SessionLayer session;
    PresentationLayer presentation;
    ApplicationLayer application;
    Result<void> send(SessionId, const StackPeer&, const core::Value&, const PayloadCipher&,
                      Encoding = Encoding::json);
    Result<std::optional<ReceivedMessage>> receive(const PayloadCipher&);
    [[nodiscard]] StackEndpoint endpoint() const;
  private:
    StackEndpoint local_;
};
} // namespace ii::network
