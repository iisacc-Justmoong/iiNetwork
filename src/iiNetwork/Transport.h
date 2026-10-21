#pragma once
#include <iiNetwork/ByteStream.h>
#include <iiSDKCore/Runtime/EventLoop.h>
#include <vector>

namespace ii::network
{
struct Interface final
{
    std::string address;
    std::uint32_t mask = 0;
    bool loopback = false, multicast = false;
    std::string name;
    std::uint32_t index = 0;
    AddressFamily family = AddressFamily::ipv4;
    std::uint8_t prefix_length = 0;
};
std::vector<Interface> interfaces();
bool local_address(std::string_view);
bool own_address(std::string_view);
bool ipv4(std::string_view);
bool ipv6(std::string_view);
struct TcpOptions final
{
    StreamOptions stream;
    bool no_delay = true, keep_alive = false;
    std::optional<IpEndpoint> bind_address;
    std::optional<int> send_buffer_bytes, receive_buffer_bytes;
};
struct ListenerOptions final
{
    int backlog = 128;
    bool reuse_address = true, ipv6_only = true;
    TcpOptions accepted_socket;
};
class LocalSocket;
class LocalServer;
class Tcp final : public ByteStream
{
  public:
    explicit Tcp(runtime::EventLoop&);
    ~Tcp() override;
    Tcp(const Tcp&) = delete;
    Tcp& operator=(const Tcp&) = delete;
    bool connect(std::string_view address, std::uint16_t port);
    Result<void> connect(IpEndpoint);
    Result<void> connect(IpEndpoint, TcpOptions);
    Result<void> configure(TcpOptions);
    Result<void> no_delay(bool);
    Result<void> keep_alive(bool);
    bool write(std::string_view) override;
    bool write(std::shared_ptr<const std::string>) override;
    std::string read() override;
    std::string read_some(std::size_t) override;
    std::string peek(std::size_t maximum = std::numeric_limits<std::size_t>::max()) const override;
    std::size_t available_bytes() const override;
    void close(bool flush = false) override;
    Result<void> shutdown_write() override;
    bool is_connected() const override;
    SocketState state() const override;
    std::string peer_address() const;
    std::string error() const override;
    void receive_limit(std::size_t) override;
    void send_limit(std::size_t) override;
    std::size_t pending_bytes() const override;
    StreamStatistics statistics() const override;
    std::optional<IpEndpoint> local_endpoint() const override;
    std::optional<IpEndpoint> peer_endpoint() const override;
    std::optional<PeerCredentials> peer_credentials() const override;
  private:
    friend class Listener;
    friend class LocalSocket;
    Result<void> connect_local(std::string_view, bool abstract_namespace, StreamOptions);
    std::string local_name(bool peer) const;
    struct Impl;
    std::unique_ptr<Impl> p_;
};
class Listener final
{
  public:
    explicit Listener(runtime::EventLoop&);
    ~Listener();
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;
    std::function<void(std::unique_ptr<Tcp>)> accepted;
    bool listen(std::uint16_t port = 0);
    bool listen(std::string_view address, std::uint16_t port = 0);
    Result<void> listen(IpEndpoint, ListenerOptions = {});
    void close();
    std::uint16_t port() const;
    std::optional<IpEndpoint> local_endpoint() const;
    std::string error() const;
  private:
    friend class LocalServer;
    Result<void> listen_local(std::string_view, bool abstract_namespace, int backlog,
                               StreamOptions, unsigned permissions, bool remove_on_close);
    std::string local_path() const;
    struct Impl;
    std::shared_ptr<Impl> p_;
};
struct Datagram final
{
    std::string bytes, address;
    std::uint16_t port = 0;
    IpEndpoint sender{};
};
struct UdpOptions final
{
    bool reuse_address = false, ipv6_only = true, broadcast = false;
    bool multicast_loopback = true;
    unsigned multicast_hops = 1;
    std::size_t maximum_datagram_bytes = 65507;
};
class Udp final
{
  public:
    explicit Udp(runtime::EventLoop&);
    ~Udp();
    Udp(const Udp&) = delete;
    Udp& operator=(const Udp&) = delete;
    std::function<void(Datagram)> received;
    std::function<void(std::string)> failed;
    bool bind(std::string_view address = "0.0.0.0", std::uint16_t port = 0);
    Result<void> bind(IpEndpoint, UdpOptions = {});
    bool bind_multicast(std::string_view group, std::uint16_t port, bool include_loopback);
    Result<void> join_multicast(IpAddress group, std::uint32_t interface_index = 0);
    Result<void> leave_multicast(IpAddress group, std::uint32_t interface_index = 0);
    Result<void> connect_peer(IpEndpoint);
    Result<void> disconnect_peer();
    Result<void> send(std::string_view, IpEndpoint);
    bool send(std::string_view, std::string_view address, std::uint16_t port);
    Result<void> write(std::string_view);
    Result<void> broadcast(bool);
    Result<void> multicast_hops(unsigned);
    Result<void> multicast_loopback(bool);
    void close();
    bool refresh_interfaces();
    std::string error() const;
    std::uint16_t port() const;
    std::optional<IpEndpoint> local_endpoint() const;
    std::optional<IpEndpoint> peer_endpoint() const;
    StreamStatistics statistics() const;
  private:
    bool start_receiving();
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
