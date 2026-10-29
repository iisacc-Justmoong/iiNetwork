# Native communication interfaces

This is the iiNetwork 0.4 C++23 communication contract. Include
`<iiNetwork/Network.h>` for native sockets, HTTP clients and TLS, and
`<iiNetwork/Server.h>` for incoming HTTP. Link `iiNetwork::iiNetwork`; public
headers expose no Qt, libcurl or OpenSSL types. `Result<T>` carries a value or
an `Error` with code, OSI responsibility layer and message.

The application relationship model is an equal peer connection. `Peer` combines
listening/dialing and publishes explicit operations; `PeerConnection` supports
mutual requests, replies and events over one TCP/TLS/local stream. Transport
setup roles do not determine application authority. See [Equal peers](Peers.md).

## Execution and common streams

Network operations, callback assignment and destruction have owner-thread
affinity. The supplied iiSDKCore `EventLoop` must outlive its objects. It runs
readiness/transfer work in bounded 5 ms timer slices. The caller pumps/runs the
loop; the module creates no per-socket threads or nested blocking loops. This
is polling integration, rather than a high-throughput completion-port backend.

`Tcp`, `LocalSocket` and `TlsStream` implement `ByteStream`:

| API | Contract |
| --- | --- |
| `write(string_view)` / `write(shared_ptr<const string>)` | Queue admission, not peer receipt. Storage is copied/retained, never borrowed after return. TCP retains shared payload storage. |
| `read()` / `read_some(maximum)` | Consume available bytes immediately; embedded NUL bytes are preserved. |
| `peek(maximum)` | Copy available data without consumption. |
| `read_exactly(count)` | Empty optional while connected/incomplete; consumes only on success; closed/incomplete is an error. |
| `read_until(delimiter, maximum)` | Same nonblocking optional contract; includes delimiter; no consumption on incomplete/oversize/error. |
| `available_bytes()` / `pending_bytes()` | Buffered readable bytes and outgoing queued work; TLS also includes ciphertext in pending work. |
| `receive_limit()` / `send_limit()` | Per-object bounds; receiving beyond the bound fails closed. |
| `statistics()` | Cumulative successful I/O bytes/operations since setup. TLS counts plaintext, not encrypted wire bytes. |
| `close(false)` | Immediate close and discard pending output. |
| `close(true)` | Attempt to drain for one second; TLS additionally sends close_notify. No delivery guarantee. |
| `shutdown_write()` | TCP/local drain then FIN; later writes fail. TLS returns unsupported. |
| `state()` / `error()` | Connection lifecycle and latest failure. |

For `Tcp`, failure to allocate the copied string or a queue entry returns
`false` without admitting the write or changing `pending_bytes()`. Existing
queued bytes remain available to drain. This does not acknowledge delivery;
callers must retain or regenerate a rejected payload and decide when to retry.
`iiNetwork.transport.allocation_shared` and `.allocation_view` exercise
ordinary C++ allocation failure on the calling thread with loopback sockets.

Callbacks are `connected`, `readable`, `bytes_written`, `drained`, `read_closed`,
`failed(message)` and `disconnected`. They may close/destroy their own object;
destruction suppresses later callbacks. Written bytes have reached the native
send path or OpenSSL plaintext write path; drained means no queued work remains.
Neither event acknowledges remote application processing. Application callbacks
should not throw; exception policy belongs at the application's loop boundary.

`StreamOptions` defaults to the legacy 513 MiB receive/send ceilings, a 10 second
connect deadline, disabled idle deadline and `allow_half_close = false`. Set
smaller bounds for application traffic. Peer FIN normally closes TCP/local
streams. Opting into half-close emits `read_closed` and permits a final response;
the socket closes once both directions finish. Idle time follows successful I/O.
Deadlines cannot exceed one year. Reconnection replaces the native connection
and resets counters. Closing retains buffered input for final reads.

## IP, TCP and UDP

`IpAddress::parse()` accepts numeric IPv4/IPv6 with IPv6 `%index`/`%interface`
scopes. Accessors provide family, scope, bytes, string, unspecified/loopback/
multicast/link-local classification and comparisons. `IpEndpoint::parse()`
accepts `127.0.0.1:443` and `[::1]:443`. `IpSubnet::parse()` accepts CIDR;
`contains()` compares prefix bits. `interfaces()` reports addresses, names,
indexes, prefixes and loopback/multicast flags, preserving the legacy IPv4 mask.

`resolve_host(host, port, family)` and `reverse_lookup(address)` are explicitly
**blocking** OS name-service utilities. Socket APIs never run implicit DNS.
Applications choose worker scheduling, endpoint retries and address-family
fallback; no automatic Happy Eyeballs scheduler is provided.

`TcpOptions` controls stream limits/deadlines, no-delay, keepalive, optional
local bind and native send/receive buffers. `configure()` applies options to an
existing socket; local bind is used only at connect. `ListenerOptions` controls
backlog, reuse-address, IPv6-only policy and accepted socket options. IPv6-only
defaults true. Endpoints report actual local/peer addresses and assigned ports.

```cpp
ii::runtime::EventLoop loop;
ii::network::Tcp socket(loop);
ii::network::TcpOptions options;
options.stream.receive_bytes = 64 * 1024;
options.stream.pending_bytes = 64 * 1024;
options.keep_alive = true;
socket.connected = [&] { if (!socket.write("hello\r\n")) socket.close(); };
socket.readable = [&] {
    auto line = socket.read_until("\r\n", 4096);
    if (!line) socket.close();
    else if (*line) { /* consume **line */ }
};
auto endpoint = ii::network::IpEndpoint::parse("[::1]:9000");
if (endpoint) {
    auto admitted = socket.connect(*endpoint, options);
    if (admitted) { /* pump loop while socket/callbacks remain alive */ }
}
```

`Udp::bind(IpEndpoint, UdpOptions)` supports IPv4/IPv6. `send(bytes, endpoint)`
emits one datagram; `received(Datagram)` carries typed sender and binary payload.
Empty datagrams are valid. `connect_peer()` enables OS peer receive filtering;
`write()` sends to that peer. Different send destinations are rejected until
`disconnect_peer()`, which retains the original bound port and rebinds if the OS
clears it. No retransmission/session reliability is added.
Some kernels, including Darwin, reset the local address to a wildcard on
disconnect while retaining the port; `local_endpoint()` reports that actual state.

`join_multicast()` / `leave_multicast()` take group and optional interface index.
Hops, loopback and IPv4 broadcast are independently configurable; IPv6 has no
broadcast. Membership/route availability depends on the OS/network.
`bind_multicast()` / `refresh_interfaces()` preserve multi-interface discovery.
Default payload bound is 65507 bytes; native maxima are 65507 for IPv4 and
65527 for IPv6. Oversized receives are dropped with `failed`.

## Local IPC

`LocalEndpoint{path}` selects filesystem AF_UNIX. Relative UTF-8 paths normalize
to absolute paths; empty/NUL/oversize paths fail. Check
`LocalSocket::maximum_path_bytes()` before provisioning (103 bytes on the tested
macOS). Client local names are normally empty; `peer_path()` reports the server.

`LocalServerOptions` supplies backlog, stream options, POSIX permissions
(default 0600) and `remove_on_close` (default true). Bind refuses every existing
entry, including stale sockets. Applications resolve stale entries themselves.
Cleanup compares recorded file identity and removes only the socket created by
that server, preserving replacement files. This identity check is not an atomic
transaction against hostile concurrent filesystem mutation; use an owned directory.

```cpp
ii::network::LocalServer server(loop);
std::vector<std::unique_ptr<ii::network::LocalSocket>> peers;
server.accepted = [&](auto stream) {
    auto* peer = stream.get();
    peer->readable = [peer] { if (!peer->write(peer->read())) peer->close(); };
    peers.push_back(std::move(stream));
};
auto listening = server.listen({"/absolute/application/directory/service.sock"});
```

`peer_credentials()` returns optional user/group/process identity: macOS exposes
user/group through getpeereid; Linux uses SO_PEERCRED including PID. Windows
credentials are unavailable. Applications authorize operations themselves. Linux
also supports abstract `LocalEndpoint{name, true}` without filesystem entries.
Windows uses AF_UNIX on supported SDK/OS versions. Named pipes/local datagrams
are not implemented. Windows/Linux source paths were not executed in this
macOS verification.

## TLS and certificate policy

`TlsContext::client(options)` / `server(options)` creates a shared immutable
context. `TlsOptions` supplies `TlsPolicy`, ALPN names, verification depth and
required client-certificate policy. `TlsPolicy` holds TLS 1.2/1.3 min/max, CA
file/directory, certificate-chain/private-key/password identity and optional
SHA-256 SPKI pin. Servers require a matching certificate/key. Clients always
verify CA trust and DNS name or IP SAN; pins add a requirement. Server pins
require mutual authentication. Obsolete SSL/TLS 1.0/1.1 cannot be selected.

Without explicit CA paths, native TLS uses OpenSSL default trust paths, which
need not match an OS keychain. Identities load at context creation and the
context clears its owned password afterward. Original caller buffers/files
and certificate renewal remain application responsibilities.

```cpp
ii::network::TlsOptions options;
options.policy.ca_file = "/absolute/trust/ca.pem";
options.alpn_protocols = {"custom/1"};
auto context = ii::network::TlsContext::client(options);
if (context) {
    ii::network::TlsStream stream(loop, *context);
    auto endpoint = ii::network::IpEndpoint::parse("127.0.0.1:9443");
    if (endpoint) {
        auto admitted = stream.connect(*endpoint, "service.example");
        // Retain stream and pump loop; connected means verification succeeded.
    }
}
```

`TlsStream::connect()` owns TCP setup. `attach(unique_ptr<ByteStream>, peer_name)`
owns an already connected callback-free TCP/local stream, including buffered
encrypted input. Clients require a peer name; servers use their context role.
No detach/downgrade operation is supplied. Custom ByteStream implementations
must honor nonblocking semantics, ownership and limits.

`TlsListener::accepted` transfers a handshaking stream: retain it and install
callbacks. Only `connected` means verification succeeded. TLS 1.3 clients may
observe local handshake completion before the server's later missing-client-
certificate refusal; subsequent failure terminates the stream. Server ALPN
preference follows its configured list.

`TlsStreamOptions` defaults to a 10 second handshake deadline, 2 MiB plaintext
receive/send and 4 MiB ciphertext. Plaintext bounds cap at 64 MiB; ciphertext
caps at 64 MiB with 16 KiB minimum. Handshake deadlines cap at 24 hours. Trust,
name, pin, timeout, overflow and unannounced EOF failures close the stream.
`close(false)` aborts; `close(true)` drains and attempts close_notify for one
second. TLS half-close is unsupported. Counters describe application plaintext.

`connection_info()` retains protocol, cipher, ALPN, server name, verification,
session-reuse observation and peer certificate. `inspect_certificate()` and
`inspect_certificate_file()` expose subject, issuer, serial, validity, SANs and
certificate/SPKI SHA-256. `valid_at()` checks dates only; inspection does not
verify chain trust. `public_key_pin()` formats curl-compatible `sha256//...`.
Session-cache controls, explicit resumption, OCSP/CRL policy and key export are
outside this interface.

## HTTP clients and servers

Each `Http` admits one request at a time. `request(request, completion)` returns
structured admission errors; legacy `start()` returns bool with `last_error()`.
Rejection has no completion. Cancel/destruction suppresses completion, including
inside upload/header/body callbacks. Callback false or upload abort produces a
transfer error if the request was not cancelled. Completion may start a new request.

| Request area | Public controls |
| --- | --- |
| Method/version | `HttpMethod`, arbitrary valid method tokens; HTTP/1.0, 1.1, 2, prior-knowledge 2, 3 or automatic |
| Fields/body | Legacy map, repeated `HeaderFields`, binary body, upload callback and optional upload size |
| Authentication | Basic, Digest, Bearer; credentials are separate from URLs |
| Cookies | Opt-in instance cookie engine, explicit request cookie, Netscape-line import/export/clear |
| Proxy | Environment/system, disabled, explicit HTTP, SOCKS5 with local/proxy DNS, credentials |
| Secure/local | TLS versions, CA paths, certificate/key/password, SPKI pin and Unix socket path |
| Transfer policy | Overall/connect/first-body/inactivity deadlines, response limit, HTTPS-only redirects, hop maximum, compression and user agent |
| Observers | Body consumer, download/full transfer progress and received headers |

Upload callbacks return at most capacity bytes, zero at EOF, or throw to abort.
Known length requires exactly that many bytes. Unknown length may use chunked
transfer, depending on backend/protocol. The bundled server rejects chunked
requests; provide upload size when targeting it. No seek/rewind callback exists,
so streamed replay after authentication/redirect can fail with a backend rewind
error; use buffered bodies when automatic replay is required. Progress runs
between curl slices; final response counters exist even if no event was emitted.

`HeaderFields` supports case-insensitive append/set/get/get_all/remove and
preserves order/repeated values. CRLF/NUL are rejected. Bounds are 128 fields,
64 KiB; response header bytes also count interim/redirect blocks. Duplicate
Host/Content-Length/Authorization and caller Transfer-Encoding are rejected.
Length must match body/upload. `ServerResponse::header_fields` supports repeated
Set-Cookie. Received-header callback runs once per header block, including
interim/redirect/authentication blocks, before its body; false aborts.

Final response multi-value fields and trailers are separate, including empty
chunked-body trailers. The legacy map contains the last value including trailers.
Response metadata includes effective URL, content type, actual version,
primary/local IP/port, redirects, native curl error, flags, transfer counts and
cumulative DNS/connect/TLS/first-byte/total milestones in microseconds.
Compressed wire counts can differ from decompressed consumed body sizes.

Cookie state lasts only within an instance. Disabled-engine requests do not
read/write its store; explicit request cookies are independent. Cookie methods
cannot run inside curl transfer callbacks. Import/export uses seven-field
Netscape lines and does not write files automatically. Explicit proxies override
environment bypass lists; Unix socket HTTP disables proxies. Redirects default
off, allow HTTPS only and default to five hops, configurable up to 32. Deadlines
cap at one year. Certificate/hostname checks are always enabled.
Pinned requests reject automatic redirects because curl pinning is origin-specific;
applications can inspect a redirect and issue a separately validated pinned request.
Cookie export fails rather than truncating when it exceeds 4096 entries.

`Http::capabilities()` reports linked libcurl version, TLS backend, IPv6,
HTTP/2/3 and Unix socket features. Unsupported version/local-socket selections
fail admission. Requested versions may permit curl negotiation/fallback;
`response.version` reports the actual version. Backend TLS versions, trust and
pin support can fail during transfer rather than admission.

`HttpServer::listen()` accepts typed IPv4/IPv6, `listen_tls()` a server context,
and `listen_local()` a local endpoint. Each shares the bounded HTTP/1.0/1.1 parser
and router/GraphQL handlers. Requests expose IP endpoints, secure flag, optional
mutual-TLS certificate and local credentials. TLS handshake and admitted HTTP
request reception have separate absolute deadlines. Close stops accepting and closes active connections;
local entry cleanup follows ownership. One Content-Length request/response is
handled per connection. HTTP/2/3 serving, keep-alive, upgrades, chunked requests
and streaming responses require a separate adapter.

REST/GraphQL continue to consume replaceable `HttpTransport` and expose protocol
bodies/errors independently of native streams. Use `Http` for the richer
low-level transfer options above.

## Primary references

- [OpenSSL hostname/IP and SNI verification](https://docs.openssl.org/3.6/man3/SSL_set1_host/)
- [OpenSSL peer verification](https://docs.openssl.org/3.6/man3/SSL_CTX_set_verify/)
- [RFC 8996: deprecating TLS 1.0/1.1](https://www.rfc-editor.org/rfc/rfc8996.html)
- [libcurl easy options](https://curl.se/libcurl/c/curl_easy_setopt.html)
- [libcurl cookie list](https://curl.se/libcurl/c/CURLOPT_COOKIELIST.html)
- [libcurl public-key pinning](https://curl.se/libcurl/c/CURLOPT_PINNEDPUBLICKEY.html)

## 메모리 TLS 식별자와 QR 신뢰

TLS 핸드셰이크 중 인증서 검증이 실패하면 실패 콜백과 `error()`는 인증서 검증 실패라는
원인을 보존한다. 이 판정은 연결별 OpenSSL 검증 상태를 사용하므로, 같은 스레드의 다른
어댑터가 OpenSSL 오류 큐를 소비하더라도 일반 연결 실패로만 축약되지 않는다.
기존 신뢰·지문·만료·용도 검사는 그대로 적용되며 거부된 연결에는 `connected`를 호출하지 않는다.

호스트와 설치 소비자 검사의 인증서 생성기는 테스트 전용 `request.cnf`를 명시적으로 사용한다.
정적 OpenSSL 도구를 다른 경로에 설치했거나 기본 `openssl.cnf`가 없는 호스트에서도
사용자의 전역 OpenSSL 설정에 의존하지 않고 같은 CA·서버·클라이언트·만료 픽스처를 생성한다.

`TlsIdentity::certificate_chain_pem`과 `private_key_pem`은 파일·키체인 없이 임시 서버 인증서를 구성한다. 파일 필드와 메모리 필드를 혼용하거나 인증서·키 중 하나만 제공하면 거부한다. `TlsPolicy::trusted_certificate_sha256`은 별도 인증된 QR·디렉터리로 확인한 정확한 leaf 인증서를 신뢰한다. 해당 지문의 일치와 인증서 유효기간을 애플리케이션 연결 콜백 전에 확인하며, 잘못된 인증서 용도나 약한 TLS 정책은 허용하지 않는다. 일반 연결의 CA·호스트명 검증과 SPKI pin 정책은 유지한다. 이 옵션은 서버 역할에서 사용할 수 없다.

`iiNetwork.interfaces.tls`는 메모리 식별자, 파일 혼용·인증서/키 불일치 거부, CA 없는 정확한 인증서 고정과 잘못된 고정값의 연결 거부를 실제 TLS 소켓으로 검증한다. 정확한 지문을 전달해도 만료된 인증서와 서버 용도가 없는 클라이언트 인증서는 거부한다.

메모리 PEM과 정확한 인증서 신뢰는 네이티브 `TlsContext`/`TlsStream` 계약이다. libcurl 기반 `Http`에 이 옵션을 전달하면 `unsupported`로 거부하여 신뢰 정책을 조용히 무시하지 않는다. HTTP의 CA·호스트명 검증과 SPKI pin은 기존 지원 범위를 따른다.

## HTTP 연결 정상 종료

`HttpServer::shutdown(grace)`는 TCP·TLS·로컬 리스너의 새 연결을 즉시 차단하고, 이미 허용한 요청과 응답은 유예 시간 안에 마무리한다. 호출은 블로킹하지 않으며 호스트는 `draining()`이 거짓이 될 때까지 이벤트 루프를 계속 구동한다. 진행 중인 종료의 반복 호출은 최초 기한을 연장하지 않는다. 최초 호출의 유예 시간이 0이면 즉시 닫고, 음수 또는 24시간 초과는 상태 변경 없이 거부한다. `close()`와 소멸자는 즉시 종료이다.

`ServerLimits::request_timeout`은 허용된 연결의 HTTP 요청 수신 절대 기한이며, `response_timeout`은 응답을 쓰고 닫는 별도의 절대 기한이다. TLS 핸드셰이크는 `TlsStreamOptions::handshake_timeout`으로 별도 제한한다. 응답을 읽지 않는 상대도 연결 슬롯을 무기한 점유하지 못한다. 동기 애플리케이션 핸들러의 C++ 실행을 선점하지 않으므로 긴 연산은 호스트 작업 큐에 넘겨야 한다. `iiNetwork.http.shutdown.*`는 진행 중 요청 완료, 새 연결 차단, 재시작, 강제 기한, 0초 종료와 응답을 읽지 않는 상대를 실제 TCP로 검증한다.

작은 HTTP 한도에서도 파서가 431·413 오류를 전송할 수 있도록 전송 수신 버퍼는 최소 64 KiB의 한 번 읽기 공간을 허용한다. 헤더·본문의 애플리케이션 한도는 파서가 별도로 적용하며, 초과 요청을 핸들러에 전달하지 않는다. 응답 기한 검사는 작은 커널 수신 버퍼와 별도 클라이언트 루프를 사용하고, 요청 전송 이후 클라이언트 읽기를 중지하여 실제 전송 정체를 재현한다.

응답 전송 큐는 검증을 마친 직렬화 응답의 실제 바이트 수로 한정한다. 본문·헤더가 각각 상한에 도달해도 상태 줄과 HTTP 프레이밍 공간 때문에 유효한 응답이 전송 단계에서 거부되지 않는다.

설치 설정의 `iiNetwork_HTTP_SERVER_LIFECYCLE`은 이 계약과 `ServerLimits` 레이아웃을 함께 제공하는 패키지의 기능 표시이다. iiWebServer는 동일 버전의 오래된 설치본과 새 HTTP 라이브러리가 섞이지 않도록 이 표시를 확인한다. 정적 라이브러리와 공개 헤더는 같은 빌드에서 설치하고 소비자는 함께 재빌드한다.
