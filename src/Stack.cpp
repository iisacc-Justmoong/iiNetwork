#include <iiNetwork/Stack.h>
#include "ProtocolInternal.h"

namespace ii::network
{
namespace
{
std::string associated_data(const SessionMessage& message, Ipv4Address source, Ipv4Address destination,
                            std::uint16_t source_port, std::uint16_t destination_port)
{
    auto bytes = SessionLayer::header(message);
    detail::put32(bytes, source.value); detail::put32(bytes, destination.value);
    detail::put16(bytes, source_port); detail::put16(bytes, destination_port);
    bytes += '\x11'; return bytes;
}
}
std::string StackPeer::identity() const { return ip.string() + ':' + std::to_string(port); }
NetworkStack::NetworkStack(runtime::EventLoop& loop, StackEndpoint local, std::shared_ptr<PhysicalMedium> medium)
    : physical(std::move(medium)), transport(loop), application(loop), local_(local) {}
StackEndpoint NetworkStack::endpoint() const { return local_; }
Result<void> NetworkStack::send(SessionId id, const StackPeer& peer, const core::Value& value,
                                const PayloadCipher& cipher, Encoding encoding)
{
    if (!local_.port || !peer.port)
        return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Stack ports must be nonzero");
    auto route = network.routes.resolve(peer.ip); if (!route) return std::unexpected(route.error());
    if (physical.medium_name().empty()) return detail::fail(Layer::physical, ErrorCode::unsupported, "No physical driver attached");
    if (route->interface_name != physical.medium_name())
        return detail::fail(Layer::network, ErrorCode::no_route, "Selected route does not use the attached medium");
    auto state = session.find(id);
    if (!state || state->peer != peer.identity())
        return detail::fail(Layer::session, ErrorCode::invalid_state, "Session peer does not match destination");
    auto encoded = presentation.encode(value, encoding); if (!encoded) return std::unexpected(encoded.error());
    // Standard Ethernet MTU minus IPv4/UDP/session/AEAD/encoding headers.
    if (encoded->size() > 1413) return detail::fail(Layer::presentation, ErrorCode::too_large, "Message exceeds authenticated Ethernet MTU");
    auto message = session.outgoing(id, {}); if (!message) return std::unexpected(message.error());
    auto plaintext = std::string(1, static_cast<char>(encoding)) + *encoded;
    auto protected_bytes = cipher.seal(plaintext, associated_data(*message, local_.ip, peer.ip, local_.port, peer.port));
    if (!protected_bytes) return std::unexpected(protected_bytes.error());
    message->payload = std::move(*protected_bytes);
    auto packed = SessionLayer::pack(*message); if (!packed) return std::unexpected(packed.error());
    auto udp = transport.encode_udp({local_.port, peer.port, std::move(*packed)}, local_.ip, peer.ip);
    if (!udp) return std::unexpected(udp.error());
    Ipv4Packet packet; packet.source = local_.ip; packet.destination = peer.ip; packet.payload = std::move(*udp);
    auto ip = network.encode(packet); if (!ip) return std::unexpected(ip.error());
    auto frame = data_link.encode({peer.next_hop_mac, local_.mac, 0x0800, std::move(*ip)});
    if (!frame) return std::unexpected(frame.error());
    return physical.transmit(*frame);
}
Result<std::optional<ReceivedMessage>> NetworkStack::receive(const PayloadCipher& cipher)
{
    auto raw = physical.receive(); if (!raw) return std::unexpected(raw.error());
    if (!*raw) return std::optional<ReceivedMessage>{};
    auto frame = data_link.decode(**raw); if (!frame) return std::unexpected(frame.error());
    if (frame->destination != local_.mac || frame->ether_type != 0x0800)
        return detail::fail(Layer::data_link, ErrorCode::unsupported, "Frame does not target this IPv4 endpoint");
    auto packet = network.decode(frame->payload); if (!packet) return std::unexpected(packet.error());
    if (packet->destination != local_.ip || packet->protocol != 17)
        return detail::fail(Layer::network, ErrorCode::unsupported, "Packet does not target this UDP endpoint");
    auto udp = transport.decode_udp(packet->payload, packet->source, packet->destination);
    if (!udp) return std::unexpected(udp.error());
    if (udp->destination_port != local_.port)
        return detail::fail(Layer::transport, ErrorCode::invalid_argument, "UDP destination port mismatch");
    auto message = SessionLayer::unpack(udp->payload); if (!message) return std::unexpected(message.error());
    StackPeer peer{packet->source, udp->source_port, frame->source};
    auto state = session.find(message->id);
    if (!state || state->peer != peer.identity())
        return detail::fail(Layer::session, ErrorCode::invalid_state, "Unknown session peer");
    auto plaintext = cipher.open(message->payload, associated_data(*message, packet->source, packet->destination,
                                                                  udp->source_port, udp->destination_port));
    if (!plaintext) return std::unexpected(plaintext.error());
    if (plaintext->empty()) return detail::fail(Layer::presentation, ErrorCode::malformed, "Missing presentation encoding");
    auto value = presentation.decode(std::string_view(*plaintext).substr(1), static_cast<Encoding>(detail::byte(*plaintext, 0)));
    if (!value) return std::unexpected(value.error());
    // Commit replay/expiry state only after both authentication and data validation.
    auto accepted = session.accept(*message); if (!accepted) return std::unexpected(accepted.error());
    return std::optional<ReceivedMessage>(ReceivedMessage{message->id, peer, std::move(*value)});
}
} // namespace ii::network
