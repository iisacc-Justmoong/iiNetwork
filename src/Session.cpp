#include <iiNetwork/Session.h>
#include "ProtocolInternal.h"
#include <openssl/rand.h>
#include <algorithm>
#include <charconv>
#include <limits>

namespace ii::network
{
using detail::fail;
namespace
{
bool empty_id(SessionId id)
{ return std::all_of(id.bytes.begin(), id.bytes.end(), [](auto b) { return b == 0; }); }
bool elapsed(const Session& session, SessionLayer::Clock::time_point now)
{ return now >= session.last_activity && now - session.last_activity >= session.idle_timeout; }
}
Result<SessionId> SessionId::generate()
{
    SessionId id;
    if (RAND_priv_bytes(id.bytes.data(), static_cast<int>(id.bytes.size())) != 1)
        return fail(Layer::session, ErrorCode::unavailable, "Session CSPRNG failed");
    id.bytes[6] = (id.bytes[6] & 15) | 64; id.bytes[8] = (id.bytes[8] & 63) | 128;
    return id;
}
Result<SessionId> SessionId::parse(std::string_view text)
{
    if (text.size() != 36) return fail(Layer::session, ErrorCode::invalid_argument, "Invalid session UUID");
    SessionId id;
    std::size_t offset = 0;
    for (unsigned i = 0; i < 16; ++i)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10)
        { if (text[offset++] != '-') return fail(Layer::session, ErrorCode::invalid_argument, "Invalid session UUID separator"); }
        unsigned value = 0;
        auto [end, error] = std::from_chars(text.data() + offset, text.data() + offset + 2, value, 16);
        if (error != std::errc{} || end != text.data() + offset + 2)
            return fail(Layer::session, ErrorCode::invalid_argument, "Invalid session UUID octet");
        id.bytes[i] = static_cast<unsigned char>(value); offset += 2;
    }
    if (empty_id(id)) return fail(Layer::session, ErrorCode::invalid_argument, "Nil session UUID");
    return id;
}
std::string SessionId::string() const
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (unsigned i = 0; i < 16; ++i)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10) result += '-';
        result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15];
    }
    return result;
}
Result<SessionId> SessionLayer::open(std::string peer, std::chrono::milliseconds timeout, Clock::time_point now)
{
    auto id = SessionId::generate(); if (!id) return std::unexpected(id.error());
    auto result = adopt(*id, std::move(peer), timeout, now);
    if (!result) return std::unexpected(result.error());
    return *id;
}
Result<void> SessionLayer::adopt(SessionId id, std::string peer, std::chrono::milliseconds timeout, Clock::time_point now)
{
    if (empty_id(id) || peer.empty() || peer.size() > 1024 || timeout.count() <= 0)
        return fail(layer, ErrorCode::invalid_argument, "Session requires ID, bounded peer and positive timeout");
    if (sessions_.contains(id)) return fail(layer, ErrorCode::invalid_state, "Session ID already exists");
    if (sessions_.size() >= capacity_) return fail(layer, ErrorCode::too_large, "Session capacity exceeded");
    sessions_.emplace(id, Session{id, std::move(peer), SessionState::active, 0, 0, now, timeout}); return {};
}
Result<Session*> SessionLayer::active(SessionId id, Clock::time_point now)
{
    auto found = sessions_.find(id);
    if (found == sessions_.end()) return fail(layer, ErrorCode::invalid_state, "Unknown session ID");
    auto& session = found->second;
    if ((session.state == SessionState::active || session.state == SessionState::suspended) && elapsed(session, now))
        session.state = SessionState::expired;
    if (session.state == SessionState::expired) return fail(layer, ErrorCode::expired, "Session has expired");
    if (session.state != SessionState::active) return fail(layer, ErrorCode::invalid_state, "Session is not active");
    return &session;
}
Result<void> SessionLayer::suspend(SessionId id, Clock::time_point now)
{
    auto result = active(id, now); if (!result) return std::unexpected(result.error());
    (*result)->state = SessionState::suspended; return {};
}
Result<void> SessionLayer::resume(SessionId id, Clock::time_point now)
{
    auto found = sessions_.find(id);
    if (found == sessions_.end()) return fail(layer, ErrorCode::invalid_state, "Unknown session ID");
    auto& session = found->second;
    if (session.state == SessionState::suspended && elapsed(session, now)) session.state = SessionState::expired;
    if (session.state == SessionState::expired) return fail(layer, ErrorCode::expired, "Session has expired");
    if (session.state != SessionState::suspended) return fail(layer, ErrorCode::invalid_state, "Only a suspended session can resume");
    session.state = SessionState::active; return {};
}
Result<void> SessionLayer::close(SessionId id)
{
    auto found = sessions_.find(id);
    if (found == sessions_.end()) return fail(layer, ErrorCode::invalid_state, "Unknown session ID");
    found->second.state = SessionState::closed; return {};
}
bool SessionLayer::erase(SessionId id) { return sessions_.erase(id) != 0; }
std::size_t SessionLayer::expire(Clock::time_point now)
{
    std::size_t count = 0;
    for (auto& [id, session] : sessions_)
        if ((session.state == SessionState::active || session.state == SessionState::suspended) && elapsed(session, now))
        { session.state = SessionState::expired; ++count; }
    return count;
}
std::optional<Session> SessionLayer::find(SessionId id) const
{
    auto found = sessions_.find(id); if (found == sessions_.end()) return {};
    return found->second;
}
Result<SessionMessage> SessionLayer::outgoing(SessionId id, std::string payload, Clock::time_point now)
{
    if (payload.size() > 1024 * 1024) return fail(layer, ErrorCode::too_large, "Session payload limit exceeded");
    auto result = active(id, now); if (!result) return std::unexpected(result.error());
    auto& session = **result;
    if (session.next_send == std::numeric_limits<std::uint64_t>::max())
        return fail(layer, ErrorCode::invalid_state, "Session sequence exhausted; establish a new session");
    session.last_activity = std::max(now, session.last_activity);
    return SessionMessage{id, session.next_send++, std::move(payload)};
}
Result<std::string> SessionLayer::accept(const SessionMessage& message, Clock::time_point now)
{
    if (message.payload.size() > 1024 * 1024) return fail(layer, ErrorCode::too_large, "Session payload limit exceeded");
    auto result = active(message.id, now); if (!result) return std::unexpected(result.error());
    auto& session = **result;
    if (message.sequence < session.next_receive) return fail(layer, ErrorCode::replay, "Session sequence already consumed");
    if (message.sequence == std::numeric_limits<std::uint64_t>::max())
        return fail(layer, ErrorCode::invalid_state, "Session sequence exhausted");
    session.next_receive = message.sequence + 1;
    session.last_activity = std::max(now, session.last_activity); return message.payload;
}
std::string SessionLayer::header(const SessionMessage& message)
{
    std::string bytes("IINS\1", 5);
    bytes.append(reinterpret_cast<const char*>(message.id.bytes.data()), 16);
    for (unsigned i = 8; i; --i) bytes += static_cast<char>(message.sequence >> ((i - 1) * 8));
    return bytes;
}
Result<std::string> SessionLayer::pack(const SessionMessage& message, std::size_t limit)
{
    if (empty_id(message.id)) return fail(layer, ErrorCode::invalid_argument, "Nil session UUID");
    if (message.payload.size() > limit) return fail(layer, ErrorCode::too_large, "Session payload limit exceeded");
    return header(message) + message.payload;
}
Result<SessionMessage> SessionLayer::unpack(std::string_view bytes, std::size_t limit)
{
    if (bytes.size() < 29 || bytes.substr(0, 5) != std::string_view("IINS\1", 5))
        return fail(layer, ErrorCode::malformed, "Invalid session wire header");
    if (bytes.size() - 29 > limit) return fail(layer, ErrorCode::too_large, "Session payload limit exceeded");
    SessionMessage message;
    std::copy_n(bytes.begin() + 5, 16, message.id.bytes.begin());
    if (empty_id(message.id)) return fail(layer, ErrorCode::malformed, "Nil session UUID");
    for (unsigned i = 21; i < 29; ++i) message.sequence = (message.sequence << 8) | detail::byte(bytes, i);
    message.payload = bytes.substr(29); return message;
}
} // namespace ii::network
