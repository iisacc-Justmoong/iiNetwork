#include <iiNetwork/Relay.h>
#include "ProtocolInternal.h"

namespace ii::network
{
struct TcpRelay::Impl : std::enable_shared_from_this<TcpRelay::Impl>
{
    std::unique_ptr<Tcp> left, right;
    std::size_t limit;
    bool active = false, started = false;
    RelayStatistics statistics;
    std::optional<Error> error;
    Impl(std::unique_ptr<Tcp> a, std::unique_ptr<Tcp> b, std::size_t count)
        : left(std::move(a)), right(std::move(b)), limit(count) {}
    static void detach(Tcp* socket)
    {
        if (!socket) return;
        socket->readable = {}; socket->connected = {}; socket->disconnected = {}; socket->failed = {};
    }
    void finish(std::optional<Error> failure = {}, bool flush = false)
    {
        active = false;
        if (failure) error = std::move(failure);
        detach(left.get()); detach(right.get());
        if (left) left->close(flush);
        if (right) right->close(flush);
    }
    void forward(bool from_left)
    {
        if (!active) return;
        auto& source = from_left ? left : right;
        auto& target = from_left ? right : left;
        auto bytes = source->read();
        if (bytes.empty()) return;
        if (bytes.size() > limit || target->pending_bytes() > limit - bytes.size() || !target->write(bytes))
        {
            finish(Error{ErrorCode::too_large, Layer::transport, "Relay pending-byte limit exceeded"}); return;
        }
        (from_left ? statistics.left_to_right : statistics.right_to_left) += bytes.size();
    }
};
TcpRelay::TcpRelay(std::unique_ptr<Tcp> left, std::unique_ptr<Tcp> right, std::size_t limit)
    : p_(std::make_shared<Impl>(std::move(left), std::move(right), limit)) {}
TcpRelay::~TcpRelay() { stop(); }
Result<void> TcpRelay::start()
{
    auto& p = *p_;
    if (p.started || !p.left || !p.right || !p.limit || !p.left->is_connected() || !p.right->is_connected())
        return detail::fail(Layer::transport, ErrorCode::invalid_state, "Relay requires two connected sockets and a positive limit");
    auto callbacks = [](const Tcp& socket) { return socket.readable || socket.connected || socket.disconnected || socket.failed; };
    if (callbacks(*p.left) || callbacks(*p.right))
        return detail::fail(Layer::transport, ErrorCode::invalid_state, "Relay sockets already have callbacks");
    p.started = p.active = true;
    auto weak = std::weak_ptr<Impl>(p_);
    for (bool from_left : {true, false})
    {
        auto& socket = from_left ? p.left : p.right;
        socket->receive_limit(p.limit); socket->send_limit(p.limit);
        socket->readable = [weak, from_left] { if (auto keep = weak.lock()) keep->forward(from_left); };
        socket->failed = [weak](std::string message)
        {
            if (auto keep = weak.lock()) keep->finish(Error{ErrorCode::io_error, Layer::transport, std::move(message)});
        };
        socket->disconnected = [weak]
        { if (auto keep = weak.lock(); keep && keep->active) keep->finish({}, true); };
    }
    p.forward(true); p.forward(false);
    if (p.error) return std::unexpected(*p.error);
    return {};
}
void TcpRelay::stop() { p_->finish(); }
bool TcpRelay::active() const { return p_->active; }
RelayStatistics TcpRelay::statistics() const { return p_->statistics; }
std::optional<Error> TcpRelay::error() const { return p_->error; }
} // namespace ii::network
