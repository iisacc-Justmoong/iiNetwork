# Verification record — 2026-10-20 (Asia/Seoul)

## Scope and environment

This record concerns iiNetwork 0.4.0 source, its workspace-staged package and
native consumers. Builds use the repository-local `build/`, with consumer
builds nested below that directory. The existing installed SDK and applications
were not replaced or restarted.

The host is macOS 27.0.1 arm64, using AppleClang 21.0.0, CMake 4.4.3, installed
iiSDKCore Runtime 0.18.1, iiJson 0.1.1, the macOS SDK's libcurl 8.7.1 headers/library
and Homebrew OpenSSL 3.6.4 Crypto/SSL. Runtime curl reports
`8.7.1; (SecureTransport) LibreSSL/3.3.6`, with HTTP/2 enabled and HTTP/3 disabled.
Native OpenSSL streams separately negotiate TLS 1.2 and TLS 1.3 in tests.
This is not a Windows/Linux/device execution
record. Public platform code paths remain separate from execution evidence.

## Completed module checks

| Check | Result |
| --- | --- |
| Release build with `-Wall -Wextra -Wpedantic` | Passed, no compiler warnings |
| Release CTest suite | 24/24 passed |
| Debug build with AddressSanitizer and UndefinedBehaviorSanitizer | Passed |
| Sanitized CTest suite | 24/24 passed; no sanitizer findings |
| Public headers compiled independently | 19/19 compiled |
| Native dependency/layer boundary policy | Passed |
| Staged `find_package(iiNetwork 0.4)` consumers | 16/16 passed |
| Source-embedded consumer with parent imports | 2/2 passed |
| Existing Congregation engine/native-backend tests | 2/2 passed with GUI disabled |
| Package inventory | 19 public headers, static library, CMake exports, license and documentation; no Finder metadata or private keys |
| Runtime dynamic dependency inspection | No Qt in iiNetwork contract executable or its iiSDKCore Runtime dependency |

The twenty-four module tests comprise twenty behavioral groups, one private TLS
fixture setup, one architecture-boundary check and two compiled examples. They exercise:

- Physical backpressure/closure/counters and Manchester transition validation.
- Ethernet padding/FCS including an independent `binascii.crc32` golden value;
  corrupted/truncated frames; IPv4 checksum/length/padding/TTL; longest-prefix
  and metric routing; UDP pseudoheader checksum and corruption detection.
- Session UUID/state transitions, capacity, expiry, peer setup and replay refusal.
- UTF-8 JSON/Base64 exchange, duplicate JSON keys and canonical Base64 padding;
  AES-256-GCM random nonces, AAD/ciphertext authentication failures and a known
  AES-256 zero-key/zero-IV empty-plaintext authentication vector.
- REST percent encoding, traversal/header injection refusal, JSON/raw binary
  request/response paths; GraphQL request fields, partial errors, explicit null,
  malformed envelopes and retained HTTP errors; static/parameter routing.
- Actual loopback UDP (including embedded NUL and empty datagrams), TCP send
  admission, REST/GraphQL over native HTTP, HEAD, body/header limits, cancellation
  and destruction from inside a libcurl stream consumer.
- Authenticated Value exchange through the entire Ethernet/IPv4/UDP/session/
  presentation pipeline on `MemoryMedium`, bidirectional exchange, MTU/peer
  checks, replay refusal and forged sequence refusal without state mutation.
- Actual bidirectional TCP relay, forwarding counters, lifecycle and overflow.
- Native HTTP server plus REST/GraphQL service roundtrips; duplicate/conflicting
  length framing, missing Host, invalid lengths, body limits, deadlines and
  unsupported transfer coding; GraphQL method/media/envelope validation.
- Numeric IPv4/IPv6 endpoints, classification/CIDR, localhost DNS and interface
  metadata; actual IPv4/IPv6 TCP local bind, options, framed/partial reads,
  half-close replies, counters and idle deadlines.
- IPv4/IPv6 connected UDP peer filtering, binary/empty datagrams, explicit peer
  destination policy, disconnect/port preservation, post-disconnect send and
  multicast membership/hop/loopback controls. Darwin disassociation resets the
  local address to wildcard; the actual endpoint is reported.
- Local AF_UNIX binary streams, peer user/group, POSIX mode, path length refusal,
  existing-file preservation, identity-checked cleanup and callback destruction.
- TLS 1.3 TCP with ALPN, certificate inspection and SPKI pin; untrusted CA,
  hostname and pin refusal; mutual authentication and missing-client-certificate
  refusal; handshake deadline, graceful close_notify and invalid option refusal.
- TLS 1.2 over local sockets, plaintext echo and destruction during the secure
  callback. Temporary CA/server/client keys are generated inside private build
  fixture directories; no private keys are installed in the package.
- HTTP duplicate Set-Cookie, opt-in cookie reuse/import/clear/disabled isolation,
  Basic/Digest/Bearer authentication, binary streamed PUT/POST, gzip decoding,
  repeated request fields, endpoint/version/timing/transfer metadata, capability
  refusal, bounded deadlines and automatic-redirect refusal on pinned requests.
- Native HTTPS CA validation, forced TLS 1.2 policy, HTTP over local sockets and
  an explicit local HTTP proxy. Chunked responses retain trailers after normal
  and empty bodies, with one header callback per block. Destruction inside a
  header callback suppresses completion.


- Equal peers over one TCP connection: simultaneous calls with the same ID in
  opposite directions, mutual state changes, bidirectional events and nested
  reverse calls before a deferred reply. Both nodes listen and dial concurrently;
  stopping listeners retains established links.
- Independent operation publication/authorization, unknown/removed operations,
  duplicate/invalid names, generic handler exceptions, negotiated frame bounds
  and separate outgoing/incoming call caps. Accepting a link grants no privilege.
- Request timeout/cooperative cancellation, absolute deadlines under delayed
  polling, late/double reply refusal, pending-call close, fresh reconnect sessions,
  node destruction and destruction during an explicit close callback. External
  closed links do not retain destroyed-node operation captures.
- Malformed JSON, pre-hello traffic, invalid versions, oversized prefixes,
  repeated hello, unsolicited replies, silent negotiation deadlines and fragmented
  frames; read EOF terminates a peer even on a half-close-enabled transport.
  IPv6, local sockets and mutual TLS all support requests in both
  directions with the same PeerConnection interface.

The first peer TDD checkpoint compiled the tests and failed to link with missing
Peer definitions; `0.4-tdd-red.log` retains that result. The compiled peer example
changes both counters over one connection (`alpha=11, beta=7`). [Peers.md](Peers.md)
specifies the private versioned protocol, trust evidence and cancellation bounds.

The fixture setup requires a local OpenSSL command and Python 3.9+. No public
endpoint or paid service is needed. libcurl HTTP/2 capability reporting is
verified; there is no HTTP/2 server or HTTP/3 network execution in this record.
SOCKS5 controls are exposed through libcurl but the executable proxy fixture
uses HTTP. Linux abstract sockets and Windows AF_UNIX/identity paths have source
implementations only. No Windows/Linux runtime claim follows from these tests.

## Reproduction

Standalone Release and staging:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$HOME/.local/SDK/iiSDKCore;$HOME/.local/SDK/iiJson;/opt/homebrew/opt/openssl@3" \
  -DCMAKE_CXX_FLAGS='-Wall -Wextra -Wpedantic' -DCMAKE_EXE_LINKER_FLAGS=''
cmake --build build -j 6
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/build/package"
```

Validation unsets `CPATH` and `LIBRARY_PATH` only for each command (`env -u
CPATH -u LIBRARY_PATH`) so ambient GUI SDK search paths cannot affect the native
check. Dependencies are resolved through CMake targets; the global environment
is unchanged.

For the sanitized checkpoint, configure the same `build/` with
`CMAKE_BUILD_TYPE=Debug`,
`CMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic'`
and `CMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'`, then build/test.
The run set `ASAN_OPTIONS=detect_stack_use_after_return=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
The final workspace build was restored to the Release configuration above.

Installed-package consumers:

```sh
cmake -S tests/consumer -B build/consumer/build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PWD/build/package;$HOME/.local/SDK/iiSDKCore;$HOME/.local/SDK/iiJson;/opt/homebrew/opt/openssl@3"
cmake --build build/consumer/build -j 4
ctest --test-dir build/consumer/build --output-on-failure
```

The consumer runs the authenticated packet example, REST/GraphQL API calls and
all seven communication-interface groups, five peer groups and the compiled
peer example against installed headers, linking
only through the exported target. A separate private TLS fixture serves those
tests. The `tests/embedded` fixture separately checks source embedding with
curl/OpenSSL already imported by a parent project and Core/iiJson first found
inside iiNetwork. Configure it in `build/embedded/build` with the dependency
prefixes above; build and run its two-example CTest suite.

Current logs use the `build/evidence/0.4-` prefix: `asan-build.log`,
`asan-ubsan.log`, `release-build.log`, `release.log`, `installed-consumer.log`,
`embedded-consumer.log`, `downstream-native-build.log`, `downstream-tests.log`,
`native-engine-targets.txt` and `linkage.txt`. Build caches and configure/install
logs retain settings and package evidence. `0.4-source-sha256.json` inventories
final source/document/test inputs; `0.4-package-inventory.json` records staged
files. The previous 0.2 checkpoint is retained under `build/evidence/0.2.0/`.
On macOS CMake installation invokes `ranlib`, changing the static archive's
index-header timestamp. Staging verification therefore compares every archived
member's bytes as well as source/header/document hashes; complete archive hashes
can differ despite identical object code.

## Existing host integration and limits

Congregation is the existing source consumer. Its configured build directory is
`/Volumes/Storage/Workspace/Product/Congregation/build`. The integration checks
build `tests_nativebackends` and `tests_applicationengine`, then run only those
two CTest entries. Other dirty product/SDK source changes are preserved.
The current host GUI configuration cannot resolve the installed LVRS macOS
platform package (`~/.local/SDK/LVRS/platforms/macos/lib/cmake/LVRS/LVRSConfig.cmake`).
Native validation therefore uses its supported `CONGREGATION_BUILD_GUI=OFF`
configuration in the same product-local build directory. The original GUI=ON
cache value is restored afterward; the restore configure result is recorded in
`0.4-downstream-results.json`. A missing GUI package does not establish a native
engine regression. Existing application bundles and installed SDKs are preserved.

The host build targets macOS 12, while installed Core, iiJson, FileProvider and
Homebrew OpenSSL dependencies were built for macOS 27. Its linker reports that
deployment-target mismatch. Execution on the current host does not establish
macOS 12 compatibility; the mismatch requires a separate dependency/package
delivery check before distributing an app for that minimum OS.

The packet driver tested here is an in-memory frame medium, not a physical NIC.
The native path uses real OS loopback sockets. No NIC signal timing, raw-device
driver, raw IPv6 packet implementation, peer discovery/NAT traversal, external GraphQL
schema engine, subscriptions, public endpoint deployment or installed-app
replacement is implied by these results. See Architecture.md for exact API
and protocol bounds.
