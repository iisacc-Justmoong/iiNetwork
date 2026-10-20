#include <iiNetwork/Layers.h>
#include <iiNetwork/Local.h>
#include "ProtocolInternal.h"
#include <algorithm>
#include <charconv>
#include <deque>
#include <mutex>

namespace ii::network
{
using detail::fail;
Result<MacAddress> MacAddress::parse(std::string_view text)
{
    if (text.size() != 17) return fail(Layer::data_link, ErrorCode::invalid_argument, "Expected six MAC octets");
    MacAddress address;
    for (unsigned i = 0; i < 6; ++i)
    {
        unsigned value = 0;
        const auto offset = i * 3;
        auto [end, error] = std::from_chars(text.data() + offset, text.data() + offset + 2, value, 16);
        if (error != std::errc{} || end != text.data() + offset + 2 ||
            (i != 5 && text[offset + 2] != ':'))
            return fail(Layer::data_link, ErrorCode::invalid_argument, "Invalid MAC address");
        address.bytes[i] = static_cast<unsigned char>(value);
    }
    return address;
}
std::string MacAddress::string() const
{
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto value : bytes)
    {
        if (!result.empty()) result += ':';
        result += hex[value >> 4]; result += hex[value & 15];
    }
    return result;
}
Result<Ipv4Address> Ipv4Address::parse(std::string_view text)
{
    Ipv4Address address;
    for (unsigned i = 0; i < 4; ++i)
    {
        auto dot = text.find('.');
        auto part = text.substr(0, dot);
        if (part.empty()) return fail(Layer::network, ErrorCode::invalid_argument, "Empty IPv4 octet");
        unsigned value = 0;
        auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), value);
        if (part.empty() || error != std::errc{} || end != part.data() + part.size() || value > 255 ||
            (part.size() > 1 && part.front() == '0') || (i == 3) != (dot == text.npos))
            return fail(Layer::network, ErrorCode::invalid_argument, "Invalid canonical IPv4 address");
        address.value = (address.value << 8) | value;
        if (dot != text.npos) text.remove_prefix(dot + 1);
    }
    return address;
}
std::string Ipv4Address::string() const
{
    return std::to_string(value >> 24) + '.' + std::to_string((value >> 16) & 255) + '.' +
           std::to_string((value >> 8) & 255) + '.' + std::to_string(value & 255);
}
struct MemoryMedium::Shared
{
    std::mutex mutex;
    std::deque<std::string> incoming[2];
    bool closed[2] = {false, false};
    std::size_t maximum_frame_size, capacity;
    Shared(std::size_t size, std::size_t count) : maximum_frame_size(size), capacity(count) {}
};
MemoryMedium::MemoryMedium(std::shared_ptr<Shared> shared, unsigned side) : shared_(std::move(shared)), side_(side) {}
MemoryMedium::~MemoryMedium() { close(); }
auto MemoryMedium::pair(std::size_t size, std::size_t count)
    -> std::pair<std::shared_ptr<MemoryMedium>, std::shared_ptr<MemoryMedium>>
{
    auto shared = std::make_shared<Shared>(size, count);
    return {std::shared_ptr<MemoryMedium>(new MemoryMedium(shared, 0)),
            std::shared_ptr<MemoryMedium>(new MemoryMedium(shared, 1))};
}
std::string MemoryMedium::name() const { return "memory"; }
std::size_t MemoryMedium::maximum_frame_size() const { return shared_->maximum_frame_size; }
Result<void> MemoryMedium::transmit(std::string_view frame)
{
    std::lock_guard lock(shared_->mutex);
    if (shared_->closed[side_] || shared_->closed[1 - side_])
        return fail(Layer::physical, ErrorCode::closed, "Memory medium is closed");
    if (frame.size() > shared_->maximum_frame_size)
        return fail(Layer::physical, ErrorCode::too_large, "Frame exceeds medium limit");
    auto& queue = shared_->incoming[1 - side_];
    if (queue.size() >= shared_->capacity)
        return fail(Layer::physical, ErrorCode::would_block, "Memory medium queue is full");
    queue.emplace_back(frame);
    return {};
}
Result<std::optional<std::string>> MemoryMedium::receive()
{
    std::lock_guard lock(shared_->mutex);
    if (shared_->closed[side_]) return fail(Layer::physical, ErrorCode::closed, "Memory medium is closed");
    auto& queue = shared_->incoming[side_];
    if (queue.empty())
    {
        if (shared_->closed[1 - side_]) return fail(Layer::physical, ErrorCode::closed, "Memory peer is closed");
        return std::optional<std::string>{};
    }
    auto frame = std::move(queue.front()); queue.pop_front();
    return std::optional<std::string>(std::move(frame));
}
void MemoryMedium::close()
{
    std::lock_guard lock(shared_->mutex);
    shared_->closed[side_] = true;
    shared_->incoming[side_].clear();
}
PhysicalLayer::PhysicalLayer(std::shared_ptr<PhysicalMedium> medium) : medium_(std::move(medium)) {}
void PhysicalLayer::attach(std::shared_ptr<PhysicalMedium> medium) { medium_ = std::move(medium); }
std::string PhysicalLayer::medium_name() const { return medium_ ? medium_->name() : std::string{}; }
std::vector<Interface> PhysicalLayer::interfaces() const { return ii::network::interfaces(); }
PhysicalStatistics PhysicalLayer::statistics() const { return statistics_; }
Result<void> PhysicalLayer::transmit(std::string_view frame)
{
    if (!medium_) return fail(layer, ErrorCode::unsupported, "No physical driver attached");
    if (frame.size() > medium_->maximum_frame_size()) return fail(layer, ErrorCode::too_large, "Frame exceeds medium limit");
    auto result = medium_->transmit(frame);
    if (result) { ++statistics_.transmitted_frames; statistics_.transmitted_bytes += frame.size(); }
    return result;
}
Result<std::optional<std::string>> PhysicalLayer::receive()
{
    if (!medium_) return fail(layer, ErrorCode::unsupported, "No physical driver attached");
    auto result = medium_->receive();
    if (result && *result)
    {
        if ((*result)->size() > medium_->maximum_frame_size()) return fail(layer, ErrorCode::too_large, "Driver returned oversized frame");
        ++statistics_.received_frames; statistics_.received_bytes += (*result)->size();
    }
    return result;
}
Result<std::string> PhysicalLayer::manchester_encode(std::string_view bytes, std::size_t limit)
{
    if (bytes.size() > limit || bytes.size() > std::string{}.max_size() / 16)
        return fail(layer, ErrorCode::too_large, "Line coding limit exceeded");
    std::string signal; signal.reserve(bytes.size() * 16);
    for (unsigned char byte : bytes) for (int bit = 7; bit >= 0; --bit)
    {
        bool high = ((byte >> bit) & 1) == 0;
        signal += static_cast<char>(high); signal += static_cast<char>(!high);
    }
    return signal;
}
Result<std::string> PhysicalLayer::manchester_decode(std::string_view signal, std::size_t limit)
{
    if (signal.size() % 16) return fail(layer, ErrorCode::malformed, "Incomplete Manchester octet");
    if (signal.size() / 16 > limit) return fail(layer, ErrorCode::too_large, "Line coding limit exceeded");
    std::string bytes; bytes.reserve(signal.size() / 16);
    unsigned value = 0;
    for (std::size_t i = 0; i < signal.size(); i += 2)
    {
        auto a = detail::byte(signal, i), b = detail::byte(signal, i + 1);
        if (a > 1 || b > 1 || a == b) return fail(layer, ErrorCode::malformed, "Invalid Manchester transition");
        value = (value << 1) | b;
        if ((i + 2) % 16 == 0) { bytes += static_cast<char>(value); value = 0; }
    }
    return bytes;
}
namespace
{
std::uint32_t crc32(std::string_view bytes)
{
    std::uint32_t crc = 0xffffffffU;
    for (unsigned char byte : bytes)
    {
        crc ^= byte;
        for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1)));
    }
    return ~crc;
}
std::uint32_t mask(unsigned bits) { return bits ? 0xffffffffU << (32 - bits) : 0; }
std::string pseudoheader(Ipv4Address source, Ipv4Address destination, std::size_t size)
{
    std::string bytes;
    detail::put32(bytes, source.value); detail::put32(bytes, destination.value);
    bytes += '\0'; bytes += '\x11'; detail::put16(bytes, static_cast<std::uint16_t>(size));
    return bytes;
}
}
Result<std::string> DataLinkLayer::encode(const EthernetFrame& frame) const
{
    if (frame.ether_type < 0x0600) return fail(layer, ErrorCode::unsupported, "Expected Ethernet II EtherType");
    if (frame.payload.size() > 1500) return fail(layer, ErrorCode::too_large, "Ethernet MTU exceeded");
    std::string out;
    out.append(reinterpret_cast<const char*>(frame.destination.bytes.data()), 6);
    out.append(reinterpret_cast<const char*>(frame.source.bytes.data()), 6);
    detail::put16(out, frame.ether_type); out += frame.payload;
    out.resize(std::max<std::size_t>(out.size(), 60), '\0');
    auto crc = crc32(out);
    for (unsigned i = 0; i < 4; ++i) out += static_cast<char>(crc >> (i * 8));
    return out;
}
Result<EthernetFrame> DataLinkLayer::decode(std::string_view frame) const
{
    if (frame.size() < 64 || frame.size() > 1518) return fail(layer, ErrorCode::malformed, "Invalid Ethernet frame length");
    std::uint32_t expected = 0;
    for (unsigned i = 0; i < 4; ++i) expected |= std::uint32_t(detail::byte(frame, frame.size() - 4 + i)) << (i * 8);
    if (crc32(frame.substr(0, frame.size() - 4)) != expected) return fail(layer, ErrorCode::checksum_mismatch, "Ethernet FCS mismatch");
    EthernetFrame result;
    std::copy_n(frame.begin(), 6, result.destination.bytes.begin());
    std::copy_n(frame.begin() + 6, 6, result.source.bytes.begin());
    result.ether_type = detail::u16(frame, 12);
    if (result.ether_type < 0x0600) return fail(layer, ErrorCode::unsupported, "802.3 LLC frames are not supported");
    result.payload = frame.substr(14, frame.size() - 18);
    return result;
}
Result<void> RoutingTable::add(Route route)
{
    if (route.prefix_length > 32 || route.interface_name.empty())
        return fail(Layer::network, ErrorCode::invalid_argument, "Invalid route prefix or interface");
    route.network.value &= mask(route.prefix_length);
    if (routes_.size() >= 4096) return fail(Layer::network, ErrorCode::too_large, "Routing table is full");
    routes_.push_back(std::move(route)); return {};
}
Result<Route> RoutingTable::resolve(Ipv4Address destination) const
{
    const Route* best = nullptr;
    for (const auto& route : routes_)
        if ((destination.value & mask(route.prefix_length)) == route.network.value &&
            (!best || route.prefix_length > best->prefix_length ||
             (route.prefix_length == best->prefix_length && route.metric < best->metric))) best = &route;
    if (!best) return fail(Layer::network, ErrorCode::no_route, "No route to destination");
    return *best;
}
void RoutingTable::clear() { routes_.clear(); }
std::size_t RoutingTable::size() const { return routes_.size(); }
Result<std::string> NetworkLayer::encode(const Ipv4Packet& packet) const
{
    if (packet.options.size() > 40 || packet.options.size() % 4)
        return fail(layer, ErrorCode::invalid_argument, "IPv4 options must be aligned and <= 40 bytes");
    const auto header_size = 20 + packet.options.size();
    if (packet.payload.size() > 65535 - header_size) return fail(layer, ErrorCode::too_large, "IPv4 length exceeded");
    if (!packet.ttl) return fail(layer, ErrorCode::ttl_expired, "IPv4 TTL is zero");
    std::string out;
    out += static_cast<char>(0x40 | (header_size / 4)); out += static_cast<char>(packet.dscp_ecn);
    detail::put16(out, static_cast<std::uint16_t>(header_size + packet.payload.size()));
    detail::put16(out, packet.identification); detail::put16(out, packet.dont_fragment ? 0x4000 : 0);
    out += static_cast<char>(packet.ttl); out += static_cast<char>(packet.protocol); detail::put16(out, 0);
    detail::put32(out, packet.source.value); detail::put32(out, packet.destination.value); out += packet.options;
    auto check = detail::checksum(out); out[10] = static_cast<char>(check >> 8); out[11] = static_cast<char>(check);
    out += packet.payload; return out;
}
Result<Ipv4Packet> NetworkLayer::decode(std::string_view bytes) const
{
    if (bytes.size() < 20 || (detail::byte(bytes, 0) >> 4) != 4)
        return fail(layer, ErrorCode::malformed, "Invalid IPv4 header");
    auto header_size = (detail::byte(bytes, 0) & 15) * 4;
    auto total = detail::u16(bytes, 2);
    if (header_size < 20 || header_size > bytes.size() || total < header_size || total > bytes.size())
        return fail(layer, ErrorCode::malformed, "Truncated IPv4 packet");
    if (bytes.size() != total && (bytes.size() != 46 || total >= 46 ||
        std::any_of(bytes.begin() + total, bytes.end(), [](char c) { return c != 0; })))
        return fail(layer, ErrorCode::malformed, "Unexpected bytes after IPv4 packet");
    if (detail::checksum(bytes.substr(0, header_size))) return fail(layer, ErrorCode::checksum_mismatch, "IPv4 header checksum mismatch");
    auto fragment = detail::u16(bytes, 6);
    if (fragment & 0x8000) return fail(layer, ErrorCode::malformed, "Reserved IPv4 flag");
    if (fragment & 0x3fff) return fail(layer, ErrorCode::unsupported, "IPv4 fragment reassembly is not available");
    if (!detail::byte(bytes, 8)) return fail(layer, ErrorCode::ttl_expired, "IPv4 TTL is zero");
    Ipv4Packet result;
    result.source.value = detail::u32(bytes, 12); result.destination.value = detail::u32(bytes, 16);
    result.protocol = static_cast<std::uint8_t>(detail::byte(bytes, 9)); result.ttl = static_cast<std::uint8_t>(detail::byte(bytes, 8));
    result.dscp_ecn = static_cast<std::uint8_t>(detail::byte(bytes, 1)); result.identification = detail::u16(bytes, 4);
    result.dont_fragment = fragment & 0x4000;
    result.options = bytes.substr(20, header_size - 20); result.payload = bytes.substr(header_size, total - header_size);
    return result;
}
Result<ForwardedPacket> NetworkLayer::forward(std::string_view bytes) const
{
    auto packet = decode(bytes); if (!packet) return std::unexpected(packet.error());
    if (!packet->options.empty()) return fail(layer, ErrorCode::unsupported, "Forwarding IPv4 options requires a policy-aware router");
    if (packet->ttl <= 1) return fail(layer, ErrorCode::ttl_expired, "IPv4 TTL exhausted at router");
    auto route = routes.resolve(packet->destination); if (!route) return std::unexpected(route.error());
    --packet->ttl;
    auto encoded = encode(*packet); if (!encoded) return std::unexpected(encoded.error());
    return ForwardedPacket{std::move(*route), std::move(*encoded)};
}
std::unique_ptr<Tcp> TransportLayer::tcp() const { return std::make_unique<Tcp>(loop_); }
std::unique_ptr<Listener> TransportLayer::listener() const { return std::make_unique<Listener>(loop_); }
std::unique_ptr<Udp> TransportLayer::udp() const { return std::make_unique<Udp>(loop_); }
std::unique_ptr<LocalSocket> TransportLayer::local_socket() const { return std::make_unique<LocalSocket>(loop_); }
std::unique_ptr<LocalServer> TransportLayer::local_server() const { return std::make_unique<LocalServer>(loop_); }
Result<std::string> TransportLayer::encode_udp(const UdpSegment& segment, Ipv4Address source, Ipv4Address destination) const
{
    if (segment.payload.size() > 65527) return fail(layer, ErrorCode::too_large, "UDP datagram length exceeded");
    if (!segment.destination_port) return fail(layer, ErrorCode::invalid_argument, "UDP destination port is zero");
    std::string out;
    detail::put16(out, segment.source_port); detail::put16(out, segment.destination_port);
    detail::put16(out, static_cast<std::uint16_t>(8 + segment.payload.size())); detail::put16(out, 0); out += segment.payload;
    auto check = detail::checksum(pseudoheader(source, destination, out.size()) + out);
    if (!check) check = 0xffff;
    out[6] = static_cast<char>(check >> 8); out[7] = static_cast<char>(check); return out;
}
Result<UdpSegment> TransportLayer::decode_udp(std::string_view bytes, Ipv4Address source, Ipv4Address destination) const
{
    if (bytes.size() < 8 || bytes.size() > 65535 || detail::u16(bytes, 4) != bytes.size() || !detail::u16(bytes, 2))
        return fail(layer, ErrorCode::malformed, "Invalid UDP length or destination port");
    // IPv4 permits a zero UDP checksum; generated segments always include one.
    if (detail::u16(bytes, 6) && detail::checksum(pseudoheader(source, destination, bytes.size()) + std::string(bytes)))
        return fail(layer, ErrorCode::checksum_mismatch, "UDP checksum mismatch");
    return UdpSegment{detail::u16(bytes, 0), detail::u16(bytes, 2), std::string(bytes.substr(8))};
}
} // namespace ii::network
