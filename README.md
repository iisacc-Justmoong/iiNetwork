# iiNetwork

iiNetwork 0.6 is the C++23 networking module of iiSDK. Its application model is
a relationship between equal peers: either side can initiate operations,
answer calls and publish events over the same connection. Listening and dialing
assign transport setup roles without application rank. A node can do both.

It provides seven OSI
responsibility objects, IPv4/IPv6 TCP/UDP, local sockets, TLS client/server streams,
HTTP/HTTPS clients and servers, REST and GraphQL adapters, session state, packet
routing, bidirectional TCP relay, presentation codecs and authenticated encryption. It imports no Qt
package or Qt public types.

`ii::network::NetworkStack` composes the seven objects, keeping application
policy and replaceable drivers outside lower layers. Existing code that includes
`iiNetwork/Network.h` and uses `Tcp`, `Listener`, `Udp`, `Http` or `Wire.h` remains
source compatible.

| Layer | Object | Implemented responsibility |
| --- | --- | --- |
| 1 Physical | `PhysicalLayer`, `PhysicalMedium` | Bounded frame I/O, driver attachment, interface inventory, counters, Manchester line codec |
| 2 Data link | `DataLinkLayer` | Ethernet II addressing, padding, MTU and CRC-32 FCS |
| 3 Network | `NetworkLayer`, `RoutingTable` | IPv4 header/checksum, longest-prefix routes, metrics and TTL-aware forwarding |
| 4 Transport | `TransportLayer`, `ByteStream`, `Tcp`, `Listener`, `Udp`, `LocalSocket`, `LocalServer` | IPv4/IPv6 and local nonblocking sockets, typed endpoints, UDP codecs/checksums, bounded send admission |
| 5 Session | `SessionLayer` | CSPRNG IDs, peer binding, suspend/resume/close/expiry, monotonic sequences |
| 6 Presentation | `PresentationLayer`, `PayloadCipher`, `Aes256Gcm`, `TlsContext`, `TlsStream` | JSON/Base64, AES-256-GCM and verified TLS 1.2/1.3 streams |
| 7 Application | `ApplicationLayer`, `RestClient`, `GraphQLClient`, `HttpRouter`, `HttpServer`, `GraphQLService`, `Peer`, `PeerConnection`, `RealtimeServer`, `RealtimeClient` | Mutual operations/events, HTTP exchange, GraphQL envelopes, native realtime sessions and room-scoped latest-value streaming |

`TcpRelay` bridges two connected sockets in both directions, enforces pending
byte limits and reports forwarding counters/errors.

The independently built [load-balancer composition](example/LoadBalancer/) selects real backend endpoints using weighted rendezvous
hashing of canonical IPv4/IPv6 TCP/UDP/TLS flow metadata. A Core `LoadLease` keeps
each established connection pinned and counted through transport cleanup; new
connections observe health, draining and resource limits. Targets added later
only receive flows for which they win the hash. See [L4 load balancing](docs/LoadBalancer.md)
and the [native loopback example](example/LoadBalancer/App/main.cpp). Applications
explicitly compose the network and runtime SDKs; the adapter is not part of the
base iiNetwork package. Existing load-balancer clients must rebuild against
`iiNetwork::LoadBalancer` from `iiNetworkLoadBalancer` and include its header
explicitly.

## Realtime state streaming

`RealtimeServer` and `RealtimeClient` provide native encrypted UDP sessions,
room-scoped relay and server publications for the same application platform:
player input, collaborative cursors, shared state and sensor updates use the
same binary latest-value channels. Per-participant tickets enter through an
authenticated TLS/IPC control plane. The data plane coalesces unsent updates,
rejects stale/replayed packets, paces traffic using RTT/receipt feedback and
enforces queue, payload, participant and lifetime limits without Qt.

Use `#include <iiNetwork/Realtime.h>` and the existing `iiNetwork::iiNetwork`
target. `example/realtime.cpp` is a compiled live-room example. Reliable
commands continue to use `Peer`/TLS alongside this state stream. See
[Realtime API, protocol and deployment](docs/Realtime.md) for admission,
authentication, loss semantics and validation scope.

## Build and consume

Dependencies are iiSDKCore >= 0.19 (Runtime), iiJson >= 0.1, libcurl >= 7.62 and
OpenSSL >= 3 (Crypto and SSL). C++23 is required. Use the repository-local `build/`.
The following installation is a workspace staging area, preserving installed SDKs.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$HOME/.local/SDK/iiSDKCore;$HOME/.local/SDK/iiJson;/opt/homebrew/opt/openssl@3"
cmake --build build -j 6
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/build/package"
```

`INSTALL_PREFIX="$PWD/build/package" BUILD_JOBS=3 ./install.sh` runs the same
source checks, installs the package and builds/runs independent installed
consumers. Omitting `INSTALL_PREFIX` selects `~/.local/SDK/iiNetwork`. New
examples live in `example/`; the older `examples/` paths remain available.

The Homebrew prefix is a macOS example; use platform-appropriate dependency
prefixes elsewhere. Consumers use the exported target:

```cmake
find_package(iiNetwork 0.4 CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE iiNetwork::iiNetwork)
```

Static library dependencies are exported. `add_subdirectory()` integration is
also supported. `IINETWORK_BUILD_TESTS` and `IINETWORK_BUILD_EXAMPLES` default on
for standalone builds and off for embedded builds.

`examples/roundtrip.cpp` is a compiled example of an authenticated Value passing
through presentation, session, UDP, IPv4, Ethernet and a paired memory medium.
`NetworkStack::send()` requires a route, established peer session, next-hop MAC
and cipher. `receive()` authenticates/decodes before committing its sequence.

## Equal peers and mutual operations

`Peer` owns exposed operations, authorization, listeners and connections.
`PeerConnection` is identical at both ends. `request()` initiates a remote
operation, `PeerReply` answers now or later, and `notify()` publishes an event.
Both directions support concurrent calls, including calls made back to the
requester while handling its operation. Request IDs are correlated by direction.

A node may listen on TCP, TLS and local sockets while dialing other nodes.
Both endpoints exchange versioned hello/session metadata before application
traffic. Only explicitly exposed operations run, with independent receiving-side
authorization; accepting a connection never grants extra remote-control rights.
Identity claims and real TLS/local credential evidence remain distinct.

See [Equal peers](docs/Peers.md) for framing, identity, deadlines, cancellation,
backpressure and lifecycle contracts. `examples/peers.cpp` is a compiled example
where the dialing and accepting nodes each change the other's counter over
one connection.

## Native communication interfaces

| Area | Public entry points | Controls and observations |
| --- | --- | --- |
| IP | `IpAddress`, `IpEndpoint`, `IpSubnet`, `interfaces()` | IPv4/IPv6, scope IDs, CIDR, names/indexes/prefixes, explicit blocking forward/reverse resolution |
| TCP | `Tcp`, `Listener`, `TcpOptions`, `ListenerOptions` | Bind/connect, IPv6-only policy, backlog, no-delay, keepalive, OS buffers, deadlines, half-close and endpoints |
| Datagram | `Udp`, `UdpOptions`, `Datagram` | Connected peer filtering, binary/empty datagrams, multicast membership/interface/hops/loopback, IPv4 broadcast and statistics |
| Local IPC | `LocalSocket`, `LocalServer`, `LocalEndpoint` | AF_UNIX streams, bounded paths, POSIX permissions/peer credentials, owned socket-file cleanup, Linux abstract namespace |
| Secure streams | `TlsContext`, `TlsStream`, `TlsListener` | TLS 1.2/1.3, CA trust, hostname/SNI, ALPN, SPKI pins, certificate/key identity, mutual authentication and negotiated metadata |
| HTTP | `Http`, `HttpRequest`, `HttpResponse`, `HeaderFields` | Methods/versions, Basic/Digest/Bearer auth, cookies, HTTP/SOCKS5 proxies, TLS policy, Unix sockets, compression, streamed transfers, progress, headers/trailers and timings |
| Incoming HTTP | `HttpServer::listen`, `listen_tls`, `listen_local` | Shared HTTP parser/router over TCP, TLS or local streams; endpoint, secure-peer and local-credential metadata |

`Tcp`, `LocalSocket` and `TlsStream` implement `ByteStream`: bounded writes,
partial/exact/delimiter reads, peek, queue sizes, callbacks and I/O counters.
See [Communication interfaces](docs/Interfaces.md) for examples, ownership,
event ordering, capability reporting and platform bounds.

## REST, GraphQL and incoming requests

Inject `NativeHttpTransport` (on a Core EventLoop) into `RestClient` or
`GraphQLClient`. A custom `HttpTransport` replaces HTTP independently. Each
transport admits one in-flight request; network APIs have owner-thread affinity.

REST has method, relative path, ordered query pairs, optional JSON/raw body and request
limits. Path/query components are percent encoded; traversal, alternate
authorities and header injection are rejected. Responses retain HTTP status,
headers, raw body and parsed JSON. Empty successful responses, including 204,
are accepted. JSON response parsing is the default; set `parse_json_response`
to false for binary/text media. Raw request media types are explicit headers.

GraphQL keeps query, operation name, variables and extensions distinct. POST
requests advertise `application/graphql-response+json` plus an `application/json`
fallback. Responses preserve partial data, explicit JSON null and structured
execution errors separately from HTTP/envelope failures.

`HttpServer` receives bounded requests over TCP, TLS or local sockets. Its handler can call
`HttpRouter::dispatch()`. `GraphQLService` mounts on that router, validates the
POST JSON envelope and serializes a supplied executor result. The application
owns schema/query validation, authorization, resolvers and complexity policy.
Incoming headers are in `GraphQLRequest::options.headers`.

## Operational boundaries

- Native TCP/UDP delegate NIC/link/IP implementation to the OS. The raw packet
  pipeline is separate. The included physical driver is `MemoryMedium`; real
  NIC/raw drivers implement `PhysicalMedium` and own signal timing. Manchester
  helpers transform in-memory symbols and do not drive hardware.
- The packet path supports Ethernet II, unfragmented IPv4 and UDP. Standard
  Ethernet MTU allows 1413 encoded application bytes with the bundled AEAD
  envelope. Next-hop MAC resolution is explicit. IPv6, ARP, VLAN, fragmentation/
  reassembly and NIC drivers are not supplied. Native TCP/UDP accepts typed
  IPv4/IPv6 endpoints; raw packet IPv6 is a separate, unimplemented capability.
- The HTTP server accepts origin-form HTTP/1.0/1.1 with Content-Length and one
  request per connection. It rejects transfer coding, ambiguous framing,
  pipelining and Expect. Upgrades, HTTP/2/3 serving, keep-alive and streaming
  responses require another adapter. HTTPS serving uses `listen_tls()`.
- HTTP/HTTPS clients retain libcurl certificate/hostname checks. Redirects
  default off; opt-in redirects target HTTPS only, with five hops by default
  and a configurable maximum of 32. HTTP/2/3 and TLS backend features depend
  on linked libcurl and are reported by `Http::capabilities()`.
- Secure stream APIs use OpenSSL TLS 1.2/1.3 and verify trust plus peer names.
  Obsolete SSL and TLS 1.0/1.1 protocols are unavailable. OpenSSL's default trust
  paths are separate from OS trust facilities used by some libcurl backends;
  pass an explicit CA file/directory when required.
- AEAD protects application payloads. Authenticated peer/key establishment is an
  application responsibility; the custom session format is not TLS. GraphQL
  subscriptions, incremental multipart delivery and a schema execution engine
  are outside these protocol adapters.

See [Architecture](docs/Architecture.md), [Communication interfaces](docs/Interfaces.md),
[Equal peers](docs/Peers.md),
[Verification](docs/Verification.md), `tests/contracts.cpp`, `tests/interfaces.cpp`
and the compiled example. Platform source paths are not
proof of execution on another OS.

## WebSocket protocol sessions

`WebSocketSession` adds RFC 6455 HTTP/1.1 upgrade, client/server framing,
fragmented text/binary messages, masking, UTF-8, ping/pong and close handling.
It consumes and produces owned byte strings over a caller-owned TCP/TLS stream.
Servers inspect and authorize `upgrade_request` before explicitly accepting it.
No networking thread, application lifetime or authentication policy is implied.
See [WebSocket contracts](docs/WebSocket.md) and `tests/websocket.cpp` for limits,
backpressure, unsupported extensions and the actual loopback integration test.

## Source header layout

Public headers and implementations live together under `src/`, grouped by responsibility; see [source layout](docs/SourceLayout.md).
There is no separate authored `include/` tree. Existing public `#include` names
and exported CMake targets are unchanged; installation still places only public
headers in the package include directory. Generated export headers belong to
`build/`, not to the authored source tree.

Validate this layout from the SDK workspace with
`python3 -B tests/test_source_header_layout.py`. Reconfigure, build, run CTest,
and verify a staged installed consumer after changing source/header paths.

<!-- workspace-docs:readme:start -->
## Documentation entry points

- Human overview: this English `README.md`.
- Agent instructions: [AGENT.md](AGENT.md).
- Human documentation: [documentation index](docs/README.md).
- Structured agent documentation: [agent index](docs/agent-index.json).
<!-- workspace-docs:readme:end -->
