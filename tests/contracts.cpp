#include <iiNetwork/Stack.h>
#include <iiNetwork/Wire.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ii::network;
using namespace std::chrono_literals;
namespace
{
void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}
template <class T, class E> T take(std::expected<T, E> result)
{
    if (!result) throw std::runtime_error(result.error().message);
    return std::move(*result);
}
void pass(Result<void> result)
{
    if (!result) throw std::runtime_error(result.error().message);
}
template <class Predicate> void until(ii::runtime::EventLoop& loop, Predicate predicate)
{
    auto deadline = ii::runtime::Clock::now() + 4s;
    while (!predicate() && ii::runtime::Clock::now() < deadline)
    {
        loop.poll();
        std::this_thread::sleep_for(1ms);
    }
    require(predicate(), "Core callback timed out");
}
auto ip(std::string_view s) { return take(Ipv4Address::parse(s)); }
auto mac(std::string_view s) { return take(MacAddress::parse(s)); }
void layers()
{
    require(!Ipv4Address::parse("1.2.3.256") && !Ipv4Address::parse("1.2.3.4x") &&
            !Ipv4Address::parse("01.2.3.4"), "invalid IPv4 accepted");
    require(ip("192.168.1.2").string() == "192.168.1.2", "IPv4 formatting");
    require(!MacAddress::parse("aa:bb:cc:dd:ee") &&
            mac("AA:bb:CC:dd:EE:ff").string() == "aa:bb:cc:dd:ee:ff", "MAC parsing");
    PhysicalLayer unattached;
    require(!unattached.transmit("x") && !unattached.receive(), "missing driver accepted");
    auto pair = MemoryMedium::pair(1518, 1);
    PhysicalLayer a(pair.first), b(pair.second);
    pass(a.transmit("abc"));
    require(!a.transmit("full"), "medium backpressure missing");
    require(take(b.receive()) == std::optional<std::string>("abc"), "physical receive");
    require(!take(b.receive()), "empty receive is not empty");
    require(a.statistics().transmitted_bytes == 3 && b.statistics().received_frames == 1,
            "physical statistics");
    auto signal = take(PhysicalLayer::manchester_encode(std::string("\x00\xff", 2)));
    require(take(PhysicalLayer::manchester_decode(signal)) == std::string("\x00\xff", 2), "line coding");
    signal[0] = signal[1];
    require(!PhysicalLayer::manchester_decode(signal), "invalid Manchester accepted");
    DataLinkLayer link;
    EthernetFrame frame{mac("01:02:03:04:05:06"), mac("06:05:04:03:02:01"), 0x0800, "abc"};
    auto bytes = take(link.encode(frame));
    require(bytes.size() == 64, "Ethernet padding/FCS size");
    require(bytes.substr(60) == std::string("\x70\x1d\x38\xd9", 4), "independent CRC-32 vector");
    auto decoded = take(link.decode(bytes));
    require(decoded.destination == frame.destination && decoded.payload.starts_with("abc"), "Ethernet decode");
    bytes[14] ^= 1;
    require(!link.decode(bytes), "corrupt FCS accepted");
    require(!link.decode(std::string(10, 'x')), "short Ethernet accepted");
    NetworkLayer network;
    Ipv4Packet packet;
    packet.source = ip("10.1.0.1"); packet.destination = ip("10.2.0.2"); packet.payload = "hello";
    auto datagram = take(network.encode(packet));
    require(take(network.decode(datagram)).payload == "hello", "IPv4 payload");
    auto damaged = datagram; damaged[8] ^= 1;
    require(!network.decode(damaged), "invalid IP checksum accepted");
    require(!network.decode(datagram.substr(0, 19)), "truncated IPv4 accepted");
    require(!network.decode(datagram + std::string(46, '\0')), "non-Ethernet padding accepted");
    pass(network.routes.add({ip("0.0.0.0"), 0, ip("10.1.0.254"), "wan", 100}));
    pass(network.routes.add({ip("10.0.0.0"), 8, {}, "lan", 20}));
    pass(network.routes.add({ip("10.2.0.0"), 16, {}, "specific", 30}));
    pass(network.routes.add({ip("10.2.0.0"), 16, {}, "preferred", 10}));
    require(take(network.routes.resolve(packet.destination)).interface_name == "preferred", "route priority");
    require(!network.routes.add({ip("10.1.2.3"), 33, {}, "bad", 0}), "invalid prefix");
    auto forwarded = take(network.forward(datagram));
    require(take(network.decode(forwarded.bytes)).ttl == 63, "TTL not decremented");
    packet.ttl = 1;
    require(!network.forward(take(network.encode(packet))), "expired TTL forwarded");
    network.routes.clear();
    require(!network.forward(datagram), "unroutable forwarded");
    ii::runtime::EventLoop loop;
    TransportLayer transport(loop);
    UdpSegment segment{1234, 5678, std::string("x\0y", 3)};
    auto udp = take(transport.encode_udp(segment, packet.source, packet.destination));
    require(take(transport.decode_udp(udp, packet.source, packet.destination)).payload == segment.payload, "UDP decode");
    udp.back() ^= 1;
    require(!transport.decode_udp(udp, packet.source, packet.destination), "UDP checksum accepted");
    pair.second->close();
    require(!a.transmit("closed"), "closed medium accepted");
}
void session()
{
    SessionLayer sessions(1);
    auto now = SessionLayer::Clock::now();
    auto id = take(sessions.open("peer", 10ms, now));
    require(take(SessionId::parse(id.string())) == id, "session ID format");
    require(!sessions.open("full", 1s, now), "session bound missing");
    auto outgoing = take(sessions.outgoing(id, "payload", now));
    auto packed = take(SessionLayer::pack(outgoing));
    auto decoded = take(SessionLayer::unpack(packed));
    require(take(sessions.accept(decoded, now)) == "payload", "session roundtrip");
    require(!sessions.accept(decoded, now), "replay accepted");
    require(!SessionLayer::unpack(packed.substr(0, 20)), "short session accepted");
    pass(sessions.suspend(id, now));
    require(!sessions.outgoing(id, "blocked", now), "suspended session sends");
    pass(sessions.resume(id, now));
    require(sessions.expire(now + 10ms) == 1 && !sessions.outgoing(id, "late", now + 10ms), "session expiry");
    require(!sessions.resume(id, now + 10ms), "expired session revived");
    require(sessions.erase(id), "session erase");
    pass(sessions.adopt(id, "peer", 1s, now));
    pass(sessions.close(id));
    require(!sessions.accept(decoded, now) && !sessions.resume(id, now), "closed session revived");
}
void presentation()
{
    PresentationLayer presentation;
    ii::core::Value value(ii::core::Value::Object{{"message", ii::core::Value("한글 😀")}});
    for (auto encoding : {Encoding::json, Encoding::base64_json})
        require(take(presentation.decode(take(presentation.encode(value, encoding)), encoding)) == value,
                "presentation roundtrip");
    require(!presentation.decode("{\"x\":1,\"x\":2}"), "duplicate JSON keys accepted");
    require(!presentation.decode("Zg==junk", Encoding::base64_json), "malformed base64 accepted");
    require(!wire::unbase64("Zg=") && !wire::unbase64("AAAA=") && !wire::unbase64("Zh==") &&
            wire::unbase64("Zg", true) == std::optional<std::string>("f"), "base64 padding/canonical bits");
    std::string field("0123456789"); std::string_view input(field); std::uint64_t number = 0;
    require(!wire::take_be(input, number, 9) && input == field, "oversized binary field accepted");
    auto key = take(Aes256Gcm::generate_key());
    Aes256Gcm cipher(key);
    auto encrypted = take(cipher.seal("secret", "context"));
    require(take(cipher.open(encrypted, "context")) == "secret", "AEAD roundtrip");
    require(take(cipher.seal("secret", "context")) != encrypted, "nonce reused");
    require(!cipher.open(encrypted, "wrong context"), "AAD mismatch accepted");
    encrypted.back() ^= 1;
    require(!cipher.open(encrypted, "context") && !cipher.open("short"), "cipher tampering accepted");
    // NIST GCM AES-256 all-zero key/IV, empty plaintext, known authentication tag.
    Aes256Gcm known(Aes256Gcm::Key{});
    std::string vector(1, '\1'); vector.append(12, '\0');
    const unsigned char tag[] = {0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b};
    vector.append(reinterpret_cast<const char*>(tag), 16);
    require(take(known.open(vector)).empty(), "NIST AES-256-GCM vector");
}
struct FakeHttp final : HttpTransport
{
    HttpRequest captured;
    HttpResponse response;
    bool start(HttpRequest request, std::function<void(HttpResponse)> done) override
    { captured = std::move(request); done(response); return true; }
    void cancel() override {}
    bool busy() const override { return false; }
};
void application()
{
    FakeHttp http;
    RestClient rest(http, "https://example.com/api/");
    RestRequest request; request.path = "items/한 글"; request.query = {{"q", "a&b"}, {"q", "+"}};
    auto prepared = take(rest.prepare(request));
    require(prepared.url == "https://example.com/api/items/%ED%95%9C%20%EA%B8%80?q=a%26b&q=%2B", "REST URL encoding");
    request.path = "../secret"; require(!rest.prepare(request), "REST traversal accepted");
    request.path = "https://evil.test"; require(!rest.prepare(request), "REST absolute URL accepted");
    request.path = "items"; request.options.headers["X-Test"] = "bad\r\nInjected: value";
    require(!rest.prepare(request), "HTTP header injection accepted");
    request.options.headers.clear();
    http.response.status = 200; http.response.body = "{\"id\":1}";
    bool complete = false;
    require(rest.request(request, [&](RestResponse r) { require(r.ok() && r.json.has_value(), "REST JSON response"); complete = true; }) && complete,
            "REST request admission");
    request.body = std::string("binary\0request", 14); request.parse_json_response = false;
    http.response.body = std::string("binary\0response", 15); complete = false;
    require(rest.request(request, [&](RestResponse r)
    { require(r.ok() && !r.json && r.http.body == http.response.body, "REST raw response"); complete = true; }) && complete && http.captured.body == *request.body,
            "REST binary exchange");
    request.json = ii::core::Value{}; require(!rest.prepare(request), "conflicting REST body formats accepted");
    GraphQLClient graphql(http, "https://example.com/graphql");
    GraphQLRequest operation; operation.query = "query Item($id: ID!) { item(id: $id) { id } }";
    operation.operation_name = "Item"; operation.variables.emplace("id", ii::core::Value("123"));
    auto graph = take(graphql.prepare(operation));
    require(graph.method == "POST" && graph.headers.at("Accept").find("application/graphql-response+json") != std::string::npos,
            "GraphQL headers");
    require(wire::text(wire::field(take(ii::json::parse(graph.body)), "operationName")) == "Item", "GraphQL envelope");
    HttpResponse raw; raw.status = 200;
    raw.body = R"({"data":{"item":null},"errors":[{"message":"missing","path":["item"],"extensions":{"code":"NOT_FOUND"}}]})";
    auto partial = GraphQLClient::decode(raw);
    require(partial.data.has_value() && partial.errors.size() == 1 && !partial.ok() && !partial.error,
            "GraphQL partial response lost");
    raw.body = R"({"data":null})";
    require(GraphQLClient::decode(raw).data.has_value(), "GraphQL explicit null lost");
    for (auto body : {"{}", "[]", R"({"errors":[]})", R"({"errors":[{}]})", R"({"data":1})"})
    { raw.body = body; require(GraphQLClient::decode(raw).error.has_value(), "invalid GraphQL envelope accepted"); }
    raw.status = 400; raw.body = R"({"errors":[{"message":"invalid query"}]})";
    auto failed = GraphQLClient::decode(raw);
    require(failed.error.has_value() && failed.errors.size() == 1, "GraphQL HTTP error metadata lost");
    HttpRouter router;
    pass(router.add("GET", "/items/{id}", [](const auto&, const auto& p) { return ServerResponse{200, {}, p.at("id")}; }));
    pass(router.add("GET", "/items/current", [](const auto&, const auto&) { return ServerResponse{200, {}, "static"}; }));
    require(!router.add("GET", "/items/{other}", [](const auto&, const auto&) { return ServerResponse{}; }), "ambiguous route accepted");
    ServerRequest incoming; incoming.target = "/items/a%20b?q=x";
    require(router.dispatch(incoming).body == "a b", "route parameter decoding");
    incoming.target = "/items/current"; require(router.dispatch(incoming).body == "static", "static route precedence");
    incoming.method = "POST"; require(router.dispatch(incoming).status == 405, "route method mismatch");
    incoming.target = "/missing"; require(router.dispatch(incoming).status == 404, "route miss");
    incoming.target = "/items/%zz"; require(router.dispatch(incoming).status == 400, "malformed route escape");
}
struct HttpServer final
{
    Listener listener;
    std::vector<std::unique_ptr<Tcp>> clients;
    std::vector<ServerRequest> requests;
    std::function<ServerResponse(const ServerRequest&)> respond;
    explicit HttpServer(ii::runtime::EventLoop& loop) : listener(loop)
    {
        listener.accepted = [this](std::unique_ptr<Tcp> socket)
        {
            auto* raw = socket.get(); auto buffer = std::make_shared<std::string>();
            raw->readable = [this, raw, buffer]
            {
                *buffer += raw->read();
                auto marker = buffer->find("\r\n\r\n"); if (marker == buffer->npos) return;
                auto first_line = buffer->find("\r\n");
                auto method_end = buffer->find(' '), target_end = buffer->find(' ', method_end + 1);
                require(target_end < first_line, "invalid HTTP fixture request");
                ServerRequest request; request.method = buffer->substr(0, method_end);
                request.target = buffer->substr(method_end + 1, target_end - method_end - 1);
                std::size_t length = 0;
                for (auto offset = first_line + 2; offset < marker;)
                {
                    auto end = buffer->find("\r\n", offset); auto colon = buffer->find(':', offset);
                    require(colon < end, "invalid HTTP fixture header");
                    auto key = wire::lower(buffer->substr(offset, colon - offset));
                    auto value = wire::trim(buffer->substr(colon + 1, end - colon - 1));
                    request.headers[key] = value;
                    if (key == "content-length") length = std::stoul(value);
                    offset = end + 2;
                }
                if (buffer->size() < marker + 4 + length) return;
                request.body = buffer->substr(marker + 4, length); requests.push_back(request);
                auto result = respond ? respond(request) : ServerResponse{200, {}, "{}"};
                std::string bytes = "HTTP/1.1 " + std::to_string(result.status) + " Fixture\r\nConnection: close\r\n";
                result.headers.emplace("Content-Type", "application/json");
                for (const auto& [key, value] : result.headers) bytes += key + ": " + value + "\r\n";
                bytes += "Content-Length: " + std::to_string(result.body.size()) + "\r\n\r\n";
                if (request.method != "HEAD") bytes += result.body;
                raw->readable = {};
                require(raw->write(bytes), "HTTP fixture write"); raw->close(true);
            };
            clients.push_back(std::move(socket));
        };
        require(listener.listen("127.0.0.1"), "HTTP fixture listen");
    }
    std::string url(std::string_view suffix = {}) const
    { return "http://127.0.0.1:" + std::to_string(listener.port()) + '/' + std::string(suffix); }
};
auto tcp_pair(ii::runtime::EventLoop& loop)
{
    Listener listener(loop); std::unique_ptr<Tcp> accepted;
    listener.accepted = [&](std::unique_ptr<Tcp> socket) { accepted = std::move(socket); };
    require(listener.listen("127.0.0.1"), "TCP pair listen");
    auto client = std::make_unique<Tcp>(loop);
    require(client->connect("127.0.0.1", listener.port()), "TCP pair connect");
    until(loop, [&] { return accepted && client->is_connected(); });
    return std::pair(std::move(client), std::move(accepted));
}
void native()
{
    ii::runtime::EventLoop loop;
    Udp a(loop), b(loop);
    require(a.bind("127.0.0.1") && b.bind("127.0.0.1") && a.port() && b.port(), "native UDP bind");
    std::vector<Datagram> received;
    b.received = [&](Datagram datagram) { received.push_back(std::move(datagram)); };
    require(a.send(std::string("a\0b", 3), "127.0.0.1", b.port()) && a.send("", "127.0.0.1", b.port()), "native UDP send");
    until(loop, [&] { return received.size() == 2; });
    require(received[0].bytes == std::string("a\0b", 3) && received[0].port == a.port() && received[1].bytes.empty(), "native UDP data");
    require(!a.send(std::string(65508, 'x'), "127.0.0.1", b.port()), "oversized UDP accepted");
    b.close(); require(!b.port(), "UDP port survives close");
    auto pair = tcp_pair(loop);
    pair.first->send_limit(3);
    require(!pair.first->write("four") && pair.first->write("abc") && pair.first->pending_bytes() == 3, "TCP send limit");
    until(loop, [&] { return pair.first->pending_bytes() == 0; });
    std::string tcp_bytes;
    until(loop, [&] { tcp_bytes += pair.second->read(); return tcp_bytes == "abc"; });
    HttpServer server(loop);
    server.respond = [](const ServerRequest& request)
    {
        if (request.target == "/graphql")
        {
            auto tree = wire::parse_json(request.body);
            require(tree && wire::text(wire::field(*tree, "operationName")) == "Item", "native GraphQL request envelope");
            return ServerResponse{200, {{"Content-Type", "application/graphql-response+json"}}, R"({"data":{"id":"123"}})"};
        }
        if (request.target == "/large") return ServerResponse{200, {}, std::string(128, 'x')};
        if (request.target == "/headers") return ServerResponse{200, {{"X-Large", std::string(65536, 'x')}}, "{}"};
        return ServerResponse{200, {}, R"({"native":true})"};
    };
    NativeHttpTransport backend(loop);
    RestClient rest(backend, server.url("api"));
    RestRequest request; request.path = "items"; request.method = "POST";
    request.json = ii::core::Value(ii::core::Value::Object{{"name", ii::core::Value("native")}});
    bool completed = false;
    require(rest.request(request, [&](RestResponse response)
    { require(response.ok() && response.json && wire::boolean(wire::field(*response.json, "native")), "native REST response"); completed = true; }), "native REST admission");
    until(loop, [&] { return completed; });
    require(server.requests.back().target == "/api/items" && server.requests.back().method == "POST", "native REST path/method");
    GraphQLClient graphql(backend, server.url("graphql"));
    GraphQLRequest operation; operation.query = "query Item { id }"; operation.operation_name = "Item";
    completed = false;
    require(graphql.execute(operation, [&](GraphQLResponse response)
    { require(response.ok() && wire::text(wire::field(*response.data, "id")) == "123", "native GraphQL response"); completed = true; }), "native GraphQL admission");
    until(loop, [&] { return completed; });
    Http raw(loop); HttpRequest limit; limit.url = server.url("large"); limit.maximum_bytes = 16;
    completed = false;
    require(raw.start(limit, [&](HttpResponse response)
    { require(response.too_large && !response.error.empty(), "HTTP response limit"); completed = true; }), "bounded HTTP admission");
    until(loop, [&] { return completed; });
    limit.url = server.url("headers"); limit.maximum_bytes = 1024; completed = false;
    require(raw.start(limit, [&](HttpResponse response)
    { require(response.too_large, "HTTP header bytes limit"); completed = true; }), "header limit admission");
    until(loop, [&] { return completed; });
    limit.url = server.url(); limit.maximum_bytes = 1024; limit.method = "HEAD";
    completed = false;
    require(raw.start(limit, [&](HttpResponse response)
    { require(response.status == 200 && response.body.empty() && response.error.empty(), "HTTP HEAD semantics"); completed = true; }), "HEAD admission");
    until(loop, [&] { return completed; });
    for (const auto& invalid : {std::string("file:///tmp/test"), std::string("http://user:secret@localhost/"), server.url() + "#fragment", std::string("http://localhost/\0hidden", 24)})
    { limit.url = invalid; require(!raw.start(limit, [](auto) {}), "unsafe HTTP URL accepted"); }
    limit.url = server.url(); limit.headers["X-Test"] = "a\r\nb";
    require(!raw.start(limit, [](auto) {}), "raw HTTP CRLF accepted"); limit.headers.clear();
    bool cancelled = false;
    require(raw.start(limit, [&](auto) { cancelled = true; }), "HTTP cancel admission");
    raw.cancel();
    auto deadline = ii::runtime::Clock::now() + 30ms;
    while (ii::runtime::Clock::now() < deadline) { loop.poll(); std::this_thread::sleep_for(1ms); }
    require(!raw.busy() && !cancelled, "cancelled HTTP callback ran");
    auto streaming = std::make_unique<Http>(loop);
    HttpRequest stream; stream.url = server.url("large");
    bool consumed = false, stream_completed = false;
    stream.consume = [&](std::string_view chunk)
    {
        require(!chunk.empty(), "empty stream chunk");
        consumed = true; streaming.reset(); return true;
    };
    require(streaming->start(stream, [&](auto) { stream_completed = true; }), "stream admission");
    until(loop, [&] { return consumed; });
    require(!streaming && !stream_completed, "destroyed stream completed");
}
void stack()
{
    ii::runtime::EventLoop loop;
    auto media = MemoryMedium::pair();
    StackEndpoint local_a{mac("02:00:00:00:00:01"), ip("10.0.0.1"), 4001};
    StackEndpoint local_b{mac("02:00:00:00:00:02"), ip("10.0.0.2"), 4002};
    NetworkStack a(loop, local_a, media.first), b(loop, local_b, media.second);
    StackPeer peer_a{local_a.ip, local_a.port, local_a.mac}, peer_b{local_b.ip, local_b.port, local_b.mac};
    auto id = take(a.session.open(peer_b.identity()));
    pass(b.session.adopt(id, peer_a.identity()));
    Aes256Gcm cipher(take(Aes256Gcm::generate_key()));
    ii::core::Value value(ii::core::Value::Object{{"message", ii::core::Value("Hello 한글")}});
    require(!a.send(id, peer_b, value, cipher), "stack sends without route");
    pass(a.network.routes.add({ip("10.0.0.0"), 24, {}, "memory", 0}));
    pass(b.network.routes.add({ip("10.0.0.0"), 24, {}, "memory", 0}));
    pass(a.send(id, peer_b, value, cipher, Encoding::base64_json));
    auto captured = take(media.second->receive()); require(captured.has_value(), "stack did not transmit");
    pass(media.first->transmit(*captured));
    auto received = take(b.receive(cipher));
    require(received && received->value == value && received->session == id && received->peer.identity() == peer_a.identity(), "stack roundtrip");
    pass(media.first->transmit(*captured));
    auto replay = b.receive(cipher);
    require(!replay && replay.error().code == ErrorCode::replay, "stack replay accepted");
    auto frame = take(b.data_link.decode(*captured));
    auto packet = take(b.network.decode(frame.payload));
    auto udp = take(b.transport.decode_udp(packet.payload, packet.source, packet.destination));
    auto message = take(SessionLayer::unpack(udp.payload)); message.sequence = 100;
    udp.payload = take(SessionLayer::pack(message));
    packet.payload = take(b.transport.encode_udp(udp, packet.source, packet.destination));
    frame.payload = take(b.network.encode(packet));
    pass(media.first->transmit(take(b.data_link.encode(frame))));
    auto tampered = b.receive(cipher);
    require(!tampered && tampered.error().code == ErrorCode::authentication_failed && b.session.find(id)->next_receive == 1,
            "unauthenticated sequence committed");
    pass(a.send(id, peer_b, value, cipher));
    require(take(b.receive(cipher))->value == value, "valid packet rejected after forged sequence");
    pass(b.send(id, peer_a, value, cipher));
    require(take(a.receive(cipher))->value == value, "reverse stack exchange");
    require(!take(a.receive(cipher)), "empty stack receive");
    require(!a.send(id, peer_b, ii::core::Value(std::string(2000, 'x')), cipher), "stack MTU missing");
    auto wrong = peer_b; wrong.port = 9999;
    require(!a.send(id, wrong, value, cipher), "session peer binding missing");
}
void relay()
{
    ii::runtime::EventLoop loop;
    auto left = tcp_pair(loop), right = tcp_pair(loop);
    TcpRelay relay(std::move(left.second), std::move(right.second), 128);
    pass(relay.start()); require(relay.active(), "relay inactive after start");
    std::string at_left, at_right;
    left.first->readable = [&] { at_left += left.first->read(); };
    right.first->readable = [&] { at_right += right.first->read(); };
    require(left.first->write("request") && right.first->write("response"), "relay client write");
    until(loop, [&] { return at_right == "request" && at_left == "response"; });
    require(relay.statistics().left_to_right == 7 && relay.statistics().right_to_left == 8, "relay statistics");
    relay.stop(); require(!relay.active() && !relay.error() && !relay.start(), "relay lifecycle");
    auto overflow_left = tcp_pair(loop), overflow_right = tcp_pair(loop);
    TcpRelay bounded(std::move(overflow_left.second), std::move(overflow_right.second), 3);
    pass(bounded.start()); require(overflow_left.first->write("too large"), "relay overflow probe");
    until(loop, [&] { return !bounded.active(); });
    require(bounded.error().has_value(), "relay overflow silently ignored");
}
std::string raw_request(ii::runtime::EventLoop& loop, std::uint16_t port, std::string bytes)
{
    Tcp socket(loop); std::string response; bool closed = false;
    socket.connected = [&] { require(socket.write(bytes), "raw request write"); };
    socket.readable = [&] { response += socket.read(); };
    socket.disconnected = [&] { closed = true; };
    require(socket.connect("127.0.0.1", port), "raw request connect");
    until(loop, [&] { return closed; }); return response;
}
void server()
{
    ii::runtime::EventLoop loop;
    GraphQLService service([](const GraphQLRequest& request)
    {
        require(request.operation_name == "Item", "GraphQL service operation name");
        GraphQLExecutionResult result;
        result.data = ii::core::Value(ii::core::Value::Object{{"id", ii::core::Value("123")}});
        return result;
    });
    HttpRouter router;
    pass(router.add("GET", "/items/{id}", [](const auto&, const auto& parameters)
    { return ServerResponse{200, {{"Content-Type", "application/json"}}, "{\"id\":\"" + parameters.at("id") + "\"}"}; }));
    pass(router.add("POST", "/graphql", [service](const auto& request, const auto&) { return service(request); }));
    ii::network::HttpServer server(loop);
    ServerLimits limits; limits.header_bytes = 1024; limits.body_bytes = 128; limits.request_timeout = 100ms;
    require(server.listen("127.0.0.1", 0, [&](const auto& request) { return router.dispatch(request); }, limits), "native HTTP server listen");
    auto base = "http://127.0.0.1:" + std::to_string(server.port());
    NativeHttpTransport backend(loop); RestClient rest(backend, base);
    RestRequest input; input.path = "items/42"; bool complete = false;
    require(rest.request(input, [&](RestResponse result)
    { require(result.ok() && wire::text(wire::field(*result.json, "id")) == "42", "native server REST result"); complete = true; }), "server REST request");
    until(loop, [&] { return complete; });
    GraphQLClient graphql(backend, base + "/graphql");
    GraphQLRequest operation; operation.query = "query Item { id }"; operation.operation_name = "Item"; complete = false;
    require(graphql.execute(operation, [&](GraphQLResponse result)
    { require(result.ok() && wire::text(wire::field(*result.data, "id")) == "123", "native server GraphQL result"); complete = true; }), "server GraphQL request");
    until(loop, [&] { return complete; });
    for (const auto& bytes : {
        "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: local\r\nBad-Header : value\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: -1\r\n\r\n"})
        require(raw_request(loop, server.port(), bytes).starts_with("HTTP/1.1 400"), "ambiguous HTTP framing accepted");
    require(raw_request(loop, server.port(), "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 129\r\n\r\n").starts_with("HTTP/1.1 413"), "server body limit");
    require(raw_request(loop, server.port(), "GET / HTTP/1.1\r\nHost: local\r\n").starts_with("HTTP/1.1 408"), "server request deadline");
    auto unsupported = raw_request(loop, server.port(), "POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    require(unsupported.starts_with("HTTP/1.1 501"), "unsupported transfer coding admitted");
    ServerRequest invalid; invalid.method = "POST"; invalid.target = "/graphql";
    invalid.headers["content-type"] = "application/json"; invalid.body = R"({"query":"{ x }","variables":[]})";
    require(service(invalid).status == 400, "GraphQL request variable shape");
    invalid.method = "GET"; require(service(invalid).status == 405, "GraphQL method policy");
    invalid.method = "POST"; invalid.headers["content-type"] = "text/plain";
    require(service(invalid).status == 415, "GraphQL media type policy");
    server.close(); require(server.port() == 0 && server.active_connections() == 0, "server close");
}
} // namespace
int main(int argc, char** argv)
{
    try
    {
        require(argc == 2, "expected contract name");
        std::string name = argv[1];
        if (name == "layers") layers(); else if (name == "session") session();
        else if (name == "presentation") presentation(); else if (name == "application") application();
        else if (name == "native") native(); else if (name == "stack") stack();
        else if (name == "relay") relay(); else if (name == "server") server();
        else throw std::runtime_error("unknown contract");
        std::cout << "PASS " << name << '\n'; return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
