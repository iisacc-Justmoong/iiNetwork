#pragma once
#include <iiNetwork/Error.h>
#include <iiNetwork/Transport.h>
#include <optional>

namespace ii::network
{
struct RelayStatistics final { std::uint64_t left_to_right = 0, right_to_left = 0; };
// Owns two connected sockets and their callbacks. Bounded admission fails closed.
class TcpRelay final
{
  public:
    TcpRelay(std::unique_ptr<Tcp> left, std::unique_ptr<Tcp> right,
             std::size_t maximum_pending_bytes = 1024 * 1024);
    ~TcpRelay();
    TcpRelay(const TcpRelay&) = delete;
    TcpRelay& operator=(const TcpRelay&) = delete;
    Result<void> start();
    void stop();
    [[nodiscard]] bool active() const;
    [[nodiscard]] RelayStatistics statistics() const;
    [[nodiscard]] std::optional<Error> error() const;
  private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};
} // namespace ii::network
