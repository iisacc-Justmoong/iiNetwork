# iiNetwork architecture and contracts

## Dependency direction

`Error.h` defines shared layer/error vocabulary. `Address.h` owns IP values;
`ByteStream.h` owns the replaceable stream contract. `Transport.h` and `Local.h`
provide OS streams/datagrams. `Security.h` owns TLS policy/certificate values;
`Tls.h` wraps `ByteStream` independently of HTTP. `Http.h` depends on policy and
header values, not native TLS implementation. `Network.h` is their umbrella.
`Layers.h` implements layers 1-4 using transport primitives. `Session.h`
depends only on shared contracts and standard types. `Presentation.h` depends
on iiJson and its cipher interface, independently of session/application state.
`Application.h` depends on HTTP and iiJson. `Server.h` adds incoming application
adapters. `Relay.h` depends on transport. `Stack.h` is the composition boundary.
`Peer.h` is an application-level symmetric operation interface over ByteStream,
with transport/TLS/session/Value dependencies. Lower layers never import Peer.
The boundary test rejects Qt and lower-layer imports of application/server/stack.

## Native and packet paths

The application relationship is between equal peers. `Peer` may listen and dial
simultaneously. `PeerConnection` gives both ends the same request/reply/event API
after mutual version/session negotiation. Each side exposes and authorizes its
own operations; connection origin provides no application privilege. Correlation,
deferred replies, cancellation and deadlines apply in both directions, including
nested reverse calls. HTTP/REST/GraphQL retain their own adapter semantics.
The private peer stream protocol and exact lifetime bounds are in [Peers](Peers.md).

The native path uses `Tcp`, `Listener`, `Udp`, `LocalSocket`, OpenSSL-backed
`TlsStream` and libcurl-backed `Http`. The OS
owns physical/link/IP implementation. Callbacks execute through the supplied
Core EventLoop in bounded 5 ms timer slices. Cancellation removes registration.
POSIX readiness uses `poll`; Windows uses Winsock. No socket worker or nested
loop is created. The EventLoop must outlive its network objects; HTTP transports
must outlive clients that borrow them. These APIs have owner-thread affinity.
Numeric parsing never does DNS. `resolve_host()` and `reverse_lookup()` are
explicitly blocking utilities. Applications choose Core worker scheduling.

The packet path uses `NetworkStack` and an injected `PhysicalMedium`:

```text
owned application Value
  -> bounded JSON or Base64(JSON)
  -> encoding byte + payload
  -> AEAD envelope, with session/endpoint context as associated data
  -> iiNetwork session header
  -> UDP datagram + IPv4 pseudoheader checksum
  -> IPv4 packet + header checksum
  -> Ethernet II frame + padding + CRC-32 FCS
  -> PhysicalMedium::transmit
```

The receiver reverses the transformations and commits receive sequence state
only after authentication and JSON decoding. Errors identify a layer and reason.
An empty successful receive is an empty `optional`; malformed input and driver
failure are errors. Unknown sessions and absent routes/drivers are rejected.

One stack owns one local endpoint and one attached medium. Routes select that
medium by name. For multiple interfaces, applications may own one stack per
medium, use `NetworkLayer::forward()` to select/re-encode a datagram and supply
the next-hop MAC on the selected output. Gateway metadata belongs to the caller's
neighbor resolution. No operation modifies the OS routing table.

## Layers 1-4

Physical drivers deliver complete Ethernet frames including FCS, excluding
preamble/SFD. Drivers for NIC APIs that strip FCS must normalize this boundary.
`PhysicalLayer` enforces size limits, reports backpressure and records admitted
frame/byte counts. `MemoryMedium` is paired, bounded and mutex-protected.
Manchester helpers use MSB-first IEEE convention: 0 = high/low, 1 = low/high;
each symbol is one byte of value 0 or 1. These helpers transform data in memory.
Hardware drivers own radio/electrical signals and timing.

Ethernet II has 6-byte destination/source addresses, a 16-bit EtherType, up to
1500 payload bytes, zero padding to 60 bytes before FCS and four CRC-32 bytes in
little-endian transmission order. Decode validates length/FCS. EtherTypes below
0x0600 (802.3 LLC) are rejected. Padding remains in decoded link payload; IPv4
removes only zero padding to Ethernet's 46-byte minimum payload.

IPv4 validates version, IHL, total length, checksum, flags and TTL. Aligned
options up to 40 bytes can be encoded/preserved; forwarding them requires an
option-aware policy and returns unsupported. Fragmented datagrams are rejected.
Basic forwarding selects longest prefix, smallest metric, then earliest inserted
route; it decrements TTL and recomputes checksum. TTL <= 1 cannot be forwarded.
The table holds at most 4096 routes. It is an application routing table.

`TransportLayer` supplies socket factories and UDP codecs. UDP validates exact
length, ports and IPv4 pseudoheader checksum. IPv4's zero/absent checksum is
accepted; generated datagrams include a checksum. `Udp::bind()` supports unicast
and ephemeral ports alongside multicast. `Tcp::send_limit()` bounds pending
admitted bytes; `pending_bytes()` reports queue size, not acknowledgement.
`close(true)` attempts to flush for up to one second. The legacy hard buffer
ceiling is 513 MiB; applications should set smaller explicit limits.

Native TCP/UDP supports IPv4 and IPv6 independently of the IPv4 packet codec.
TCP/local streams share `ByteStream`: partial/exact/delimiter reads, peek,
counters, queue bounds and callbacks. Half-close is opt-in with
`allow_half_close`; `shutdown_write()` drains admitted output before FIN.
Socket options and endpoint metadata are explicit. UDP uses OS peer association
for filtering and rejects different destinations until disconnected. Disconnect
preserves the bound port, rebinding if the kernel clears it. Darwin uses
`disconnectx()` to disassociate its peer.

Local streams use AF_UNIX. Servers refuse existing filesystem entries, set
POSIX permissions and remove only their own recorded socket-file identity at
close. Replacement files survive. Abstract names require Linux. Peer credentials
are optional OS identity evidence; applications authorize their own operations.
See Interfaces.md for path, ownership and OS bounds.

TLS owns an underlying stream and uses OpenSSL memory BIOs with independent
plaintext/ciphertext bounds and a handshake deadline. Native descriptors and
OpenSSL types remain private. Immutable `TlsContext` owns trust, identity,
versions, ALPN and verification. Clients verify chain and DNS name/IP SAN;
SPKI pins add a check. Servers may require a verified client certificate.
Accepted streams are handshaking; only `connected` means secure. Graceful close
drains and sends close_notify with a one-second deadline; unannounced EOF fails
as truncation. Weak dispatch and retained state support callback-local destruction.

## Session, presentation and security

A session has a CSPRNG UUID, explicit peer identity, active/suspended/closed/
expired state, independent sequences and an idle deadline. `open()` creates a
local record; `adopt()` installs an explicitly established remote record. Neither
authenticates a peer. Suspended sessions stop exchange; only unexpired suspended
sessions can resume. Closed/expired sessions remain terminal. `find()` returns
the last recorded snapshot; `expire()` and operations enforce current deadlines.
Terminal records retain capacity until `erase()`. Default capacity is 1024.

Sequences never wrap. Receive sequences must increase, allowing UDP gaps;
duplicates and late reordered messages are rejected. Failed sends may consume a
reserved number, so retries use a new number. This is ordered, lossy datagram
session policy; reliable streams use TCP. Low-level `SessionLayer::accept()`
requires prior authentication. `NetworkStack::receive()` enforces that ordering.

Private session v1 is `IINS` + byte 1 + 16 UUID bytes + unsigned 64-bit big-endian
sequence + payload: 29 header bytes, with a default 1 MiB payload bound. A fresh
ID is required for a new establishment. Erasing/reusing an ID resets replay
state; records are in memory and do not form a durable reconnect protocol.

`PresentationLayer` uses bounded iiJson and canonical Base64. Duplicate JSON
keys, malformed UTF-8, excessive depth/items/bytes and invalid Base64 padding
are rejected. The cipher is replaceable through `PayloadCipher`.
`Aes256Gcm` uses OpenSSL EVP, a 256-bit key, fresh random 96-bit nonce and 128-bit
tag. Envelope: byte 1 + nonce + tag + ciphertext (29 bytes overhead). Limits are
64 MiB payload and 64 KiB associated data. Authentication failure cleanses the
provisional plaintext. The cipher cleanses its owned key copy; callers own any
original key buffers. Keys are neither logged nor stored by the module.

The stack authenticates session header, source/destination IPs, ports and UDP
protocol number. Encoding is encrypted. MAC/TTL/checksum fields remain mutable
for routing. Applications supply authenticated key establishment; IDs are not
key exchange and the custom wire format is not TLS. Standard Ethernet MTU gives
a 1413-byte encoded application budget with the bundled cipher. Other ciphers
still pass through final UDP/IP/Ethernet MTU validation.

## HTTP, REST and GraphQL

`HttpTransport::start()` returning false means no admission and no callback.
Each transport has one in-flight request; use separate instances for concurrency.
Cancel suppresses completion. Native HTTP defers cleanup if cancelled/destroyed
inside a stream consumer. Completion can start another request. Explicit inputs
bound deadlines/body bytes and provide stream/progress callbacks. Response
headers are capped at 128 fields and 64 KiB aggregate bytes. Credentials in URLs,
fragments, controls, non-HTTP schemes and CRLF injection are rejected. libcurl's
certificate/hostname verification remains enabled. Redirects default off; opt-in
redirects permit HTTPS only and default to five hops (configurable up to 32).
All deadlines cap at one year. Versions are checked against linked libcurl
features; negotiation/fallback follows curl, and response metadata reports the
actual version.

`HeaderFields` retains repeated fields separately from trailers, including
empty-body trailers. Legacy maps retain the last field value. Basic/Digest/
Bearer authentication, opt-in per-instance cookies, explicit HTTP/SOCKS5 proxies,
CA/identity/pin policy, compression, Unix sockets and streamed uploads are request
options. Explicit proxies override environment bypass; local HTTP disables
proxies. Only opted-in requests use the cookie store. Upload streams have no
rewind contract; buffered bodies support backend replay. Progress, endpoints,
native errors, counts and cumulative timing milestones are response evidence.
`request()` provides structured admission errors; `start()` preserves bool
compatibility. Cancel defers cleanup inside upload/header/body callbacks and
suppresses completion. Interfaces.md specifies callback and lifetime rules.

REST independently encodes relative path/query components and retains repeated
query names. Dot traversal and alternate authorities are rejected. An optional
JSON body uses iiJson. Responses retain raw HTTP evidence and parsed JSON.
Empty successful responses are accepted. JSON decoding is the default;
`parse_json_response = false` preserves arbitrary binary/text response bodies.
Request `json` and raw `body` are mutually exclusive; raw media types are caller
headers. Streaming exchanges use `Http`.

GraphQL clients send POST JSON with query, operation name, variables/extensions.
They advertise `application/graphql-response+json` plus an `application/json`
fallback. Explicit null differs from absent data. Error message/path/location/
extension shapes are validated. Partial data survives execution errors. HTTP
and malformed-envelope failures are separate from GraphQL errors; `ok()` requires
successful HTTP, valid data and no errors. No schema/parser/resolvers are inferred.

`HttpRouter` matches methods and origin-form paths. `{name}` captures one segment.
Static segments outrank parameterized matches; equal specificity follows
registration order. Duplicate shapes/names are rejected. Parameters decode once;
encoded slash/NUL/backslash and traversal are rejected. Query text is ignored for
matching. Misses produce 404/405 with Allow; handler exceptions produce 500.

`HttpServer` receives one Content-Length-framed request per connection and closes
after responding. Limits default to 64 connections, 16 KiB headers, 2 MiB request/
response bodies and a 10 second absolute request deadline. Excess connections are
closed. Duplicate framing/Host headers, invalid lengths, conflicting framing,
missing HTTP/1.1 Host, header folding, oversize and pipelining are rejected.
Responses are validated before serialization. Transfer coding, Expect, upgrades,
keep-alive and streaming responses require another adapter. `listen_tls()` and
`listen_local()` use the same parser over `ByteStream`; requests report secure
transport, endpoints, client certificate and optional local credentials.
Handshake time counts toward the absolute request deadline.

`GraphQLService` mounts on a router handler and owns POST JSON envelope validation
and response serialization. Its application executor receives a `GraphQLRequest`
and returns `GraphQLExecutionResult`. The application owns schemas, query
validation, authorization/resolvers and complexity policy. Incoming headers are
available in `operation.options.headers`. Optional fields accept absence/null.
Subscriptions and multipart incremental delivery are outside this adapter.

```cpp
ii::runtime::EventLoop loop;
ii::network::HttpRouter router;
ii::network::GraphQLService graph([](const ii::network::GraphQLRequest& operation) {
    // Authorize using operation.options.headers; validate and execute the query.
    ii::network::GraphQLExecutionResult result;
    result.data = ii::core::Value(ii::core::Value::Object{
        {"service", ii::core::Value("iiNetwork")}});
    return result;
});
auto registration = router.add("POST", "/graphql", [graph](const auto& req, const auto&) {
    return graph(req);
});
ii::network::HttpServer server(loop);
bool listening = registration && server.listen("127.0.0.1", 8080,
    [&](const auto& request) { return router.dispatch(request); });
// Propagate listen failure; pump loop only while all borrowed objects are alive.
if (listening) loop.run();
```

## Relay

`TcpRelay` owns two already connected sockets with no installed callbacks.
`start()` registers both directions, sets buffer limits and forwards buffered
input. Counters record admitted forwarding bytes. Pending-byte overflow fails
closed and retains an error. Peer disconnect stops both directions and attempts
to flush admitted output. `stop()`/destruction remove callbacks and close sockets.
Instances are not restartable. This is a byte-stream relay, not an OS IP router
or an HTTP CONNECT parser.

## References

- [ITU-T X.200 OSI model](https://www.itu.int/rec/T-REC-X.200/en)
- [RFC 791 IPv4](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 768 UDP](https://www.rfc-editor.org/rfc/rfc768)
- [RFC 9112 HTTP/1.1 framing](https://www.rfc-editor.org/rfc/rfc9112.html)
- [GraphQL over HTTP draft](https://http-spec.graphql.org/draft/)
- [OpenSSL EVP authenticated encryption](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/)
