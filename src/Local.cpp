#include <iiNetwork/Local.h>
#include "SocketInternal.h"

namespace ii::network
{
namespace
{
Result<LocalEndpoint> normalize(LocalEndpoint endpoint)
{
    if (!endpoint.abstract_namespace)
    {
        if (endpoint.path.empty() || endpoint.path.find('\0') != endpoint.path.npos)
            return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Invalid local socket path");
        std::error_code error;
        auto path = std::filesystem::absolute(detail::utf8_path(endpoint.path), error).lexically_normal().u8string();
        if (error) return detail::fail(Layer::transport, ErrorCode::invalid_argument, "Local socket path normalization failed");
        endpoint.path.assign(reinterpret_cast<const char*>(path.data()), path.size());
    }
    auto address = native::local_address(endpoint.path, endpoint.abstract_namespace);
    if (!address) return std::unexpected(address.error()); return endpoint;
}
}
struct LocalSocket::Impl
{
    std::unique_ptr<Tcp> stream; LocalSocket* owner = nullptr; bool alive = true;
    explicit Impl(std::unique_ptr<Tcp> value) : stream(std::move(value)) {}
};
LocalSocket::LocalSocket(runtime::EventLoop& loop) : LocalSocket(std::make_unique<Tcp>(loop)) {}
LocalSocket::LocalSocket(std::unique_ptr<Tcp> stream) : p_(std::make_shared<Impl>(std::move(stream)))
{ p_->owner = this; callbacks(); }
void LocalSocket::callbacks()
{
    auto weak = std::weak_ptr<Impl>(p_);
    auto event = [weak](std::function<void()> ByteStream::* member)
    {
        if (auto keep = weak.lock(); keep && keep->alive)
        { auto callback = keep->owner->*member; if (callback) callback(); }
    };
    p_->stream->connected = [event] { event(&ByteStream::connected); };
    p_->stream->readable = [event] { event(&ByteStream::readable); };
    p_->stream->disconnected = [event] { event(&ByteStream::disconnected); };
    p_->stream->drained = [event] { event(&ByteStream::drained); };
    p_->stream->read_closed = [event] { event(&ByteStream::read_closed); };
    p_->stream->failed = [weak](std::string message)
    { if (auto keep = weak.lock(); keep && keep->alive) { auto callback = keep->owner->failed; if (callback) callback(std::move(message)); } };
    p_->stream->bytes_written = [weak](std::size_t size)
    { if (auto keep = weak.lock(); keep && keep->alive) { auto callback = keep->owner->bytes_written; if (callback) callback(size); } };
}
LocalSocket::~LocalSocket() { p_->alive = false; p_->stream->close(); }
Result<void> LocalSocket::connect(LocalEndpoint endpoint, StreamOptions options)
{ auto name = normalize(std::move(endpoint)); if (!name) return std::unexpected(name.error()); return p_->stream->connect_local(name->path, name->abstract_namespace, options); }
bool LocalSocket::write(std::string_view bytes) { return p_->stream->write(bytes); }
std::string LocalSocket::read() { return p_->stream->read(); }
std::string LocalSocket::read_some(std::size_t maximum) { return p_->stream->read_some(maximum); }
std::string LocalSocket::peek(std::size_t maximum) const { return p_->stream->peek(maximum); }
std::size_t LocalSocket::available_bytes() const { return p_->stream->available_bytes(); }
std::size_t LocalSocket::pending_bytes() const { return p_->stream->pending_bytes(); }
void LocalSocket::receive_limit(std::size_t bytes) { p_->stream->receive_limit(bytes); }
void LocalSocket::send_limit(std::size_t bytes) { p_->stream->send_limit(bytes); }
void LocalSocket::close(bool flush) { p_->stream->close(flush); }
Result<void> LocalSocket::shutdown_write() { return p_->stream->shutdown_write(); }
bool LocalSocket::is_connected() const { return p_->stream->is_connected(); }
SocketState LocalSocket::state() const { return p_->stream->state(); }
std::string LocalSocket::error() const { return p_->stream->error(); }
StreamStatistics LocalSocket::statistics() const { return p_->stream->statistics(); }
std::optional<PeerCredentials> LocalSocket::peer_credentials() const { return p_->stream->peer_credentials(); }
std::string LocalSocket::local_path() const { return p_->stream->local_name(false); }
std::string LocalSocket::peer_path() const { return p_->stream->local_name(true); }
std::size_t LocalSocket::maximum_path_bytes() { return sizeof(sockaddr_un{}.sun_path) - 1; }
struct LocalServer::Impl
{
    Listener listener; LocalServer* owner; bool alive = true;
    Impl(runtime::EventLoop& loop, LocalServer* value) : listener(loop), owner(value) {}
};
LocalServer::LocalServer(runtime::EventLoop& loop) : p_(std::make_shared<Impl>(loop, this))
{
    p_->listener.accepted = [weak = std::weak_ptr<Impl>(p_)](std::unique_ptr<Tcp> stream)
    {
        auto keep = weak.lock(); if (!keep || !keep->alive) return;
        auto callback = keep->owner->accepted;
        if (callback) callback(std::unique_ptr<LocalSocket>(new LocalSocket(std::move(stream))));
    };
}
LocalServer::~LocalServer() { p_->alive = false; close(); }
Result<void> LocalServer::listen(LocalEndpoint endpoint, LocalServerOptions options)
{
    auto name = normalize(std::move(endpoint)); if (!name) return std::unexpected(name.error());
    return p_->listener.listen_local(name->path, name->abstract_namespace, options.backlog, options.stream, options.permissions, options.remove_on_close);
}
void LocalServer::close() { p_->listener.close(); }
std::string LocalServer::path() const { return p_->listener.local_path(); }
std::string LocalServer::error() const { return p_->listener.error(); }
} // namespace ii::network
