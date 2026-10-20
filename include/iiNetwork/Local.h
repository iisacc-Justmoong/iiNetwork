#pragma once
#include <iiNetwork/Transport.h>

namespace ii::network
{
struct LocalEndpoint final
{
    std::string path;
    bool abstract_namespace = false; // Linux only; no filesystem entry
};
struct LocalServerOptions final
{
    int backlog = 128;
    StreamOptions stream;
    unsigned permissions = 0600; // POSIX filesystem sockets
    bool remove_on_close = true; // only the entry created by this listener
};
class LocalSocket final : public ByteStream
{
  public:
    explicit LocalSocket(runtime::EventLoop&);
    ~LocalSocket() override;
    LocalSocket(const LocalSocket&) = delete;
    LocalSocket& operator=(const LocalSocket&) = delete;
    Result<void> connect(LocalEndpoint, StreamOptions = {});
    using ByteStream::write;
    bool write(std::string_view) override;
    std::string read() override;
    std::string read_some(std::size_t) override;
    std::string peek(std::size_t maximum = std::numeric_limits<std::size_t>::max()) const override;
    std::size_t available_bytes() const override;
    std::size_t pending_bytes() const override;
    void receive_limit(std::size_t) override;
    void send_limit(std::size_t) override;
    void close(bool flush = false) override;
    Result<void> shutdown_write() override;
    bool is_connected() const override;
    SocketState state() const override;
    std::string error() const override;
    StreamStatistics statistics() const override;
    std::optional<PeerCredentials> peer_credentials() const override;
    [[nodiscard]] std::string local_path() const;
    [[nodiscard]] std::string peer_path() const;
    [[nodiscard]] static std::size_t maximum_path_bytes();
  private:
    friend class LocalServer;
    struct Impl;
    std::shared_ptr<Impl> p_;
    explicit LocalSocket(std::unique_ptr<Tcp>);
    void callbacks();
};
class LocalServer final
{
  public:
    explicit LocalServer(runtime::EventLoop&);
    ~LocalServer();
    LocalServer(const LocalServer&) = delete;
    LocalServer& operator=(const LocalServer&) = delete;
    std::function<void(std::unique_ptr<LocalSocket>)> accepted;
    Result<void> listen(LocalEndpoint, LocalServerOptions = {});
    void close();
    [[nodiscard]] std::string path() const;
    [[nodiscard]] std::string error() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
