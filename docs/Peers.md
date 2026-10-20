# Equal peers and mutual operations

The primary application model is a relationship between equal peers. Listening
and dialing select how a transport is established; they assign no application
authority. Either end of one connection can initiate requests, answer requests,
publish events and authorize incoming operations concurrently. Each node can
listen and dial at the same time. TCP, TLS and local socket roles stay within
transport setup. HTTP/REST/GraphQL remain adapters with their own protocol rules.

`Peer` is the node: it owns operation registration, authorization, listeners and
connections. `PeerConnection` is the identical connection object at both ends.
`expose()` explicitly publishes a named operation. A request invokes only a
registered operation and must pass that receiving node's authorizer. Listening
never grants the listener extra rights over the dialing node. No OS command,
object method or process state is published implicitly.

Connections first exchange versioned hello frames, identity claims, fresh local
session IDs and frame bounds. Both send hello independently. A ready connection
has sent and received hello; request/event traffic before that fails. Both sides
may use request ID 1 simultaneously: response correlation is scoped to the
request's direction. Stream framing preserves messages across partial/coalesced
reads. Connection-specific IDs and reply handles never migrate to a new link.

Peer names are claims, not cryptographic identity. `PeerInfo` retains actual
TLS verification/certificate and local socket credential evidence independently.
An application can require mutual TLS and bind a certificate to a logical name
in its authorizer. Plain TCP supplies no identity authentication or encryption.
Protocol symmetry does not force applications to grant identical permissions.
Both peers make their own decisions using the same mechanism.

## Operations and lifetime

All APIs, deferred replies and callbacks belong to the supplied Core EventLoop's
owner thread. No worker or nested blocking wait is created. `PeerCall` owns its
arguments and retains the connection; a handler may issue a reverse request on
that connection before replying. Copyable `PeerReply` can be retained for later
completion on the loop. It rejects double replies and replies after cancellation,
timeout or disconnect. Handler exceptions become a generic remote error without
exposing exception text. Other application callbacks should not throw.

`request()` admits a bounded operation and returns its direction-local ID. A
rejected call has no completion. An admitted call completes once with value,
remote error, timeout or close, unless explicitly cancelled or its node is
destroyed. `cancel()` suppresses the local completion and attempts cooperative
remote cancellation. Its boolean reports local removal; queued cancellation is
best effort under backpressure. `PeerReply::cancelled()` also becomes true when the receiver
deadline or connection expires. Cancellation does not roll back side effects or
stop application work automatically. Callers use cancellation-aware Core tasks
for expensive work. Automatic replay/reconnect is not performed for operations.

`notify()` admits an event without response correlation. Its return value does
not acknowledge remote processing. Notifications invoke the receiving link's
`received` callback; applications validate topics/data there. The operation
authorizer applies to calls, not to notification observers.

`connected` on a link runs first, then the node's common `connected(link)` hook.
Both are emitted only after negotiation and apply equally to accepted and dialed
links. Transport or framing failures are reported on link/node failure hooks.
`close()` stops a connection and settles pending calls. `Peer::close()` stops
all listeners/links while retaining operation registration for a later reopen.
Destruction closes links and suppresses pending callbacks. Reply handles become
cancelled; external connection handles may remain, but are closed. The loop must
outlive nodes and all objects that continue using it.
Remote close/cancellation observation happens when the other endpoint pumps its
loop. Node destruction releases operation/authorizer captures even when callers
retain closed connection handles. Call deadlines are absolute: delayed polling
cannot make an expired reply successful.
A peer relationship requires both directions. Read EOF ends the relationship
even if the underlying TCP/local socket was configured to allow half-close.

TCP, TLS and local listeners can coexist within one node. Re-listening replaces
only that transport's listener. `stop_listening()` leaves established links
alive. `connect_tls()` and `listen_tls()` retain TLS handshake roles internally;
mutual TLS is selected in their contexts. `attach()` takes ownership of a
connected/connecting callback-free ByteStream, including a handshaking TlsStream.

## Bounds and private wire format

`PeerLimits` defaults to 1 MiB frames, 2 MiB queued output, 64 links, 64 outgoing
and 64 incoming calls per link, 128 registered operations, a 10 second negotiation
deadline and a 60 second maximum call timeout. A request defaults to 10 seconds.
Frames range from 512 bytes to 16 MiB; pending bytes range from one full frame
plus prefix to 64 MiB. Link/call/operation counts cap at 4096, and handshake/call
deadlines cap at one hour. Invalid options fail admission. The receiver clamps
the supplied call budget to its own maximum. Receive storage and parsing slices
are bounded. Backpressure is a reported admission failure.

The private `iin-peer/1` protocol uses an unsigned 32-bit network-order length
followed by bounded UTF-8 JSON. This format is not HTTP, REST, GraphQL or a public
RPC standard. Hello advertises version 1, logical identity, fresh session UUID
and maximum frame bytes. Messages have these exact shapes:

```json
{"type":"hello","version":1,"identity":"alpha","session":"01234567-89ab-4cde-8fab-0123456789ab","maximum_frame":1048576}
{"type":"call","id":"1","operation":"counter.add","arguments":2,"timeout":10000}
{"type":"result","id":"1","value":3}
{"type":"error","id":"1","code":"permission_denied","layer":7,"message":"Operation denied"}
{"type":"event","topic":"counter.changed","value":3}
{"type":"cancel","id":"1"}
```

IDs are decimal strings to preserve 64-bit values without JSON number rounding.
Call IDs increase independently in each direction and never wrap. A duplicate
or decreasing incoming call ID, repeated hello, unknown version/type, unsolicited
future result, malformed schema/JSON or oversized frame fails the link. Late
results for settled/cancelled calls are ignored. Names are bounded ASCII operation
tokens; JSON data remains UTF-8 Value data. Frame size is negotiated to the smaller
peer bound for outgoing application messages. TLS/local credential evidence is
collected from the real transport, never supplied by the hello payload.

Peer discovery, NAT traversal, relay discovery, distributed consensus, persistent
remote object replication and automatic permission sharing are not implemented.
They are separate application/network mechanisms; none is inferred from equal
peer status. The existing packet `NetworkStack` and session/encryption APIs remain
available independently of this stream-based peer protocol.
