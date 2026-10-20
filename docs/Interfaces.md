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
mutual-TLS certificate and local credentials. Handshake time counts toward the
absolute request deadline. Close stops accepting and closes active connections;
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
