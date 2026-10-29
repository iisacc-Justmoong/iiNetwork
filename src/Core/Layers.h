#pragma once
#include <iiNetwork/Error.h>
#include <iiNetwork/Transport.h>
#include <array>
#include <compare>
#include <optional>
#include <utility>

namespace ii::network
{
class LocalSocket;
class LocalServer;
struct MacAddress final
{
    std::array<unsigned char, 6> bytes{};
    static Result<MacAddress> parse(std::string_view);
    [[nodiscard]] std::string string() const;
    auto operator<=>(const MacAddress&) const = default;
};
struct Ipv4Address final
{
    std::uint32_t value = 0; // host-independent, most significant octet first
    static Result<Ipv4Address> parse(std::string_view);
    [[nodiscard]] std::string string() const;
    auto operator<=>(const Ipv4Address&) const = default;
};

// A frame-preserving driver boundary. Real NIC drivers own modulation and timing.
// Nonblocking: an empty optional means no frame; errors must never mean no data.
class PhysicalMedium
{
  public:
    virtual ~PhysicalMedium() = default;
    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual std::size_t maximum_frame_size() const = 0;
    virtual Result<void> transmit(std::string_view frame) = 0;
    virtual Result<std::optional<std::string>> receive() = 0;
};
class MemoryMedium final : public PhysicalMedium
{
  public:
    static std::pair<std::shared_ptr<MemoryMedium>, std::shared_ptr<MemoryMedium>>
        pair(std::size_t maximum_frame_size = 1518, std::size_t capacity = 64);
    ~MemoryMedium() override;
    MemoryMedium(const MemoryMedium&) = delete;
    MemoryMedium& operator=(const MemoryMedium&) = delete;
    [[nodiscard]] std::string name() const override;
    [[nodiscard]] std::size_t maximum_frame_size() const override;
    Result<void> transmit(std::string_view) override;
    Result<std::optional<std::string>> receive() override;
    void close();
  private:
    struct Shared;
    MemoryMedium(std::shared_ptr<Shared>, unsigned side);
    std::shared_ptr<Shared> shared_;
    unsigned side_;
};
struct PhysicalStatistics final
{
    std::uint64_t transmitted_frames = 0, received_frames = 0;
    std::uint64_t transmitted_bytes = 0, received_bytes = 0;
};
class PhysicalLayer final
{
  public:
    static constexpr Layer layer = Layer::physical;
    explicit PhysicalLayer(std::shared_ptr<PhysicalMedium> medium = {});
    void attach(std::shared_ptr<PhysicalMedium>);
    [[nodiscard]] std::string medium_name() const;
    [[nodiscard]] std::vector<Interface> interfaces() const;
    Result<void> transmit(std::string_view);
    Result<std::optional<std::string>> receive();
    [[nodiscard]] PhysicalStatistics statistics() const;
    // IEEE Manchester convention: 0 = high/low, 1 = low/high, bytes MSB first.
    static Result<std::string> manchester_encode(std::string_view, std::size_t limit = 1518);
    static Result<std::string> manchester_decode(std::string_view, std::size_t limit = 1518);
  private:
    std::shared_ptr<PhysicalMedium> medium_;
    PhysicalStatistics statistics_;
};
struct EthernetFrame final
{
    MacAddress destination, source;
    std::uint16_t ether_type = 0x0800;
    std::string payload;
};
class DataLinkLayer final
{
  public:
    static constexpr Layer layer = Layer::data_link;
    // Ethernet II: includes zero padding and little-endian CRC-32 FCS, no preamble.
    Result<std::string> encode(const EthernetFrame&) const;
    Result<EthernetFrame> decode(std::string_view) const;
};
struct Ipv4Packet final
{
    Ipv4Address source, destination;
    std::uint8_t protocol = 17, ttl = 64, dscp_ecn = 0;
    std::uint16_t identification = 0;
    bool dont_fragment = true;
    std::string options, payload;
};
struct Route final
{
    Ipv4Address network;
    std::uint8_t prefix_length = 0;
    std::optional<Ipv4Address> gateway;
    std::string interface_name;
    std::uint32_t metric = 0;
};
class RoutingTable final
{
  public:
    Result<void> add(Route);
    [[nodiscard]] Result<Route> resolve(Ipv4Address) const;
    void clear();
    [[nodiscard]] std::size_t size() const;
  private:
    std::vector<Route> routes_;
};
struct ForwardedPacket final { Route route; std::string bytes; };
class NetworkLayer final
{
  public:
    static constexpr Layer layer = Layer::network;
    RoutingTable routes;
    Result<std::string> encode(const Ipv4Packet&) const;
    // Zero Ethernet padding is accepted only up to the 46-byte minimum payload.
    Result<Ipv4Packet> decode(std::string_view) const;
    Result<ForwardedPacket> forward(std::string_view) const;
};
struct UdpSegment final
{
    std::uint16_t source_port = 0, destination_port = 0;
    std::string payload;
};
class TransportLayer final
{
  public:
    static constexpr Layer layer = Layer::transport;
    explicit TransportLayer(runtime::EventLoop& loop) : loop_(loop) {}
    [[nodiscard]] std::unique_ptr<Tcp> tcp() const;
    [[nodiscard]] std::unique_ptr<Listener> listener() const;
    [[nodiscard]] std::unique_ptr<Udp> udp() const;
    [[nodiscard]] std::unique_ptr<LocalSocket> local_socket() const;
    [[nodiscard]] std::unique_ptr<LocalServer> local_server() const;
    Result<std::string> encode_udp(const UdpSegment&, Ipv4Address source, Ipv4Address destination) const;
    Result<UdpSegment> decode_udp(std::string_view, Ipv4Address source, Ipv4Address destination) const;
  private:
    runtime::EventLoop& loop_;
};
} // namespace ii::network
