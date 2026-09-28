# Build and ownership

Place zal-net beside this checkout, or set `ZAL_NET_DIR`.
Build AWS-LC with `scripts/awslc-setup.sh`; `ci/aws-lc.ref` pins its source.
Use the same unchanged Nimony revision as zal-net.

```sh
NIMONY=../zal-net/build/toolchain/bin/nimony scripts/test.sh
NIMONY=../zal-net/build/toolchain/bin/nimony SUITE=full scripts/test.sh
```

`AWSLC` selects an existing AWS-LC installation. Windows uses the PowerShell
setup and test scripts. `scripts/test-ktls.sh` requires native Linux kTLS.
Generated output stays under ignored `build/` directories.

Configurations retain immutable keys, trust and provider contexts. Connections
retain configurations and their transports through handshake and cleanup.
Borrowed transports require an explicit lifetime owner in safe constructors.
Protocol state machines do not depend on sockets or scheduling.

One reader and one writer may coexist. Writes and control records preserve
record order. Locks cover bounded state changes and are released before waits.
Close cancels new admission and joins pending operations and background tasks.
A deadline never permits releasing storage still used by an operation.
Ambiguous partial protocol progress makes the connection unusable; do not replay.
TLS wraps only public zal-net interfaces. QUIC mode is a handshake API, not a
QUIC transport. Certificate verification is enabled.

Platform availability is checked by native tests. AWS-LC is a separate dependency
with its own licenses; it is not vendored here.
