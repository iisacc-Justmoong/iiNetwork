#pragma once
#include <iiNetwork/Headers.h>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace ii::network {
enum class WebSocketState { upgrading, awaiting_acceptance, open, closing, closed, failed };
struct WebSocketLimits final {
    std::size_t handshake_bytes=16384, message_bytes=8*1024*1024;
    std::size_t buffered_bytes=16*1024*1024, output_bytes=16*1024*1024, events=1024;
};
struct WebSocketClient final {
    std::string host, target="/", origin;
    std::vector<std::string> protocols;
    HeaderFields headers;
};
struct WebSocketUpgrade final {
    std::string host, target, origin;
    std::vector<std::string> protocols;
    HeaderFields headers;
};
enum class WebSocketEventKind { upgrade_request, opened, text, binary, ping, pong, closed };
struct WebSocketEvent final {
    WebSocketEventKind kind;
    std::string payload;
    std::uint16_t close_code=0;
};
// RFC 6455 protocol state over a caller-owned TCP/TLS/IPC byte stream.
// No socket, scheduler, callback or application lifetime is implicitly owned.
class WebSocketSession final {
public:
    ~WebSocketSession();
    WebSocketSession(WebSocketSession&&) noexcept;
    WebSocketSession& operator=(WebSocketSession&&) noexcept;
    WebSocketSession(const WebSocketSession&)=delete;
    WebSocketSession& operator=(const WebSocketSession&)=delete;
    [[nodiscard]] static Result<WebSocketSession> client(WebSocketClient,WebSocketLimits={});
    [[nodiscard]] static Result<WebSocketSession> server(WebSocketLimits={});
    [[nodiscard]] Result<std::vector<WebSocketEvent>> receive(std::string_view bytes);
    // The server must inspect upgrade(), authorize the request, then accept.
    [[nodiscard]] const WebSocketUpgrade* upgrade() const noexcept;
    [[nodiscard]] Result<void> accept(std::string_view protocol={});
    [[nodiscard]] Result<void> reject(unsigned status=403);
    [[nodiscard]] Result<void> send_text(std::string_view);
    [[nodiscard]] Result<void> send_binary(std::string_view);
    [[nodiscard]] Result<void> ping(std::string_view={});
    [[nodiscard]] Result<void> close(std::uint16_t code=1000,std::string_view reason={});
    // Keep returned bytes until the transport admits them; this is a move-out.
    [[nodiscard]] std::string take_output();
    [[nodiscard]] WebSocketState state() const noexcept;
    [[nodiscard]] std::string protocol() const;
private:
    struct State;
    std::unique_ptr<State> state_;
    explicit WebSocketSession(std::unique_ptr<State>);
};
}
