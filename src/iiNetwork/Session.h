#pragma once
#include <iiNetwork/Error.h>
#include <array>
#include <chrono>
#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <string_view>

namespace ii::network
{
struct SessionId final
{
    std::array<unsigned char, 16> bytes{};
    static Result<SessionId> generate();
    static Result<SessionId> parse(std::string_view);
    [[nodiscard]] std::string string() const;
    auto operator<=>(const SessionId&) const = default;
};
enum class SessionState { active, suspended, closed, expired };
struct Session final
{
    SessionId id;
    std::string peer;
    SessionState state = SessionState::active;
    std::uint64_t next_send = 0, next_receive = 0;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::milliseconds idle_timeout{300000};
};
struct SessionMessage final
{
    SessionId id;
    std::uint64_t sequence = 0;
    std::string payload;
};
class SessionLayer final
{
  public:
    using Clock = std::chrono::steady_clock;
    static constexpr Layer layer = Layer::session;
    explicit SessionLayer(std::size_t capacity = 1024) : capacity_(capacity) {}
    SessionLayer(const SessionLayer&) = delete;
    SessionLayer& operator=(const SessionLayer&) = delete;
    Result<SessionId> open(std::string peer, std::chrono::milliseconds idle_timeout = std::chrono::minutes(5),
                           Clock::time_point now = Clock::now());
    // Peer setup/key agreement is explicit; receiving an unknown ID never creates a session.
    Result<void> adopt(SessionId, std::string peer, std::chrono::milliseconds idle_timeout = std::chrono::minutes(5),
                       Clock::time_point now = Clock::now());
    Result<void> suspend(SessionId, Clock::time_point now = Clock::now());
    Result<void> resume(SessionId, Clock::time_point now = Clock::now());
    Result<void> close(SessionId);
    bool erase(SessionId);
    std::size_t expire(Clock::time_point now = Clock::now());
    [[nodiscard]] std::optional<Session> find(SessionId) const;
    Result<SessionMessage> outgoing(SessionId, std::string payload, Clock::time_point now = Clock::now());
    // Call only after authentication; monotonically increasing sequences allow UDP gaps.
    Result<std::string> accept(const SessionMessage&, Clock::time_point now = Clock::now());
    static std::string header(const SessionMessage&);
    static Result<std::string> pack(const SessionMessage&, std::size_t limit = 1024 * 1024);
    static Result<SessionMessage> unpack(std::string_view, std::size_t limit = 1024 * 1024);
  private:
    Result<Session*> active(SessionId, Clock::time_point);
    std::map<SessionId, Session> sessions_;
    std::size_t capacity_;
};
} // namespace ii::network
