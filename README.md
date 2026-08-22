# sqns

Resolution of sQUIC public keys to network endpoints.

An sQUIC service is identified by an Ed25519 public key, and reached at a
`sqc://host:port/<base58 key>` address. sqns answers the middle part of that
string: **given the key, where is it right now?**

```
$ sqns resolve 2mTFsr7ozzywfcCzRENivZcWiFPpbbuejGXe61oRX1eu
198.51.100.4:443
[2001:db8::5]:443
backup.example.com:4433
```

Keys stay fixed while addresses move. A node publishes where it can be reached,
signed by the key it is publishing for, and refreshes that record on a timer;
anything holding the key can look it up. When a key does have to change — a
breach, a rebuild — lookups of the old one **forward to the new one**, so the
callers still holding it are carried across rather than stranded.

## Why not DNS

sqns is not a DNS server and speaks no DNS. There are no names, no zones and no
referrals — the lookup key is a 32-byte Ed25519 public key, and an answer comes
from one server or not at all. Answers are signed by that key, or by the
identity that issued it, so verification needs no CA, no DNSSEC chain and no
trust in the server that answered.

| | DNS | sqns |
|---|---|---|
| Lookup key | hierarchical name | Ed25519 public key |
| Answer | records signed by the zone, if DNSSEC | always signed by the key, or by the identity behind it |
| Trust | resolver chain and CAs | the key you already had |
| Transport | UDP/53, DoT, DoH, DoQ | sQUIC only |
| Key compromise | reissue from the CA or zone | retire the key; lookups forward to its replacement |
| Server visibility | responds to anyone | silent to anyone without its public key |

## Install

```
curl -fsSL https://raw.githubusercontent.com/wave-cl/sqns/main/install.sh | sh
```

Installs `sqns` and `sqnsd` to `/usr/local/bin` (root) or `~/.local/bin`
(non-root). Linux and macOS, x86_64 and aarch64. Run with `--server` for server
setup: key, config, systemd unit.

## Getting started

Point at a server, then four commands to a published service:

```bash
export SQNS_SERVER=sqc://ns1.example.com:5300/<server key>

sqns keygen --identity            # your identity key — keep this offline
sqns keygen                       # a service key for this node
sqns delegate                     # the identity issues it authority
sqns publish -e 198.51.100.4:443  # publish where you can be reached
```

From anywhere:

```bash
sqns resolve <service key>
```

Keys live in `~/.sqns` (mode 0700): `identity.key`, `service.key`, and the
delegation between them, `service.deleg`. Every command takes explicit paths
too, which is how you run several services from one host:

```bash
sqns publish --key-file ~/.sqns/web.key --delegation ~/.sqns/web.deleg -e '198.51.100.4:443'
```

Instead of exporting `SQNS_SERVER`, you can list servers in `~/.sqns/config`,
one `sqc://` address per line, `#` for comments.

A long-running node should hold its record open, which republishes inside the
TTL and withdraws the key on exit:

```bash
sqns publish -e '198.51.100.4:443' --ttl 300 --keepalive
```

### Three nodes, one identity

Three nodes of one service are three service keys, each with its own private
key on its own host — nothing is ever copied between machines.

```bash
# Offline, once per node
for n in 1 2 3; do
  sqns keygen --out ~/.sqns/ns$n.key
  sqns delegate --service-key ~/.sqns/ns$n.key --out ~/.sqns/ns$n.deleg
done

# On each node, holding only its own key and delegation
sqns publish --key-file ~/.sqns/ns1.key --delegation ~/.sqns/ns1.deleg \
  -e '198.51.100.1:443'
```

Each resolves under its own public key, is rotated or revoked without touching
the others, and the identity can list them all:

```bash
sqns identity <identity>
```

### Try it without a server

```bash
./scripts/demo.sh
```

Runs the whole thing on loopback in a temporary directory — three services
under one identity, rotating one key, revoking another, restarting the server —
and cleans up after itself, touching neither `~/.sqns` nor your system.
`KEEP=1 ./scripts/demo.sh` leaves the server up so you can poke at it.

## Running a server

```bash
sqnsd
```

With no arguments it generates a key on first run and prints the connection
string clients need. Defaults are `/etc/sqns/sqnsd.key` and
`/var/lib/sqns/records.db` as root, `~/.sqns/sqnsd.key` and
`~/.sqns/records.db` otherwise, listening on `[::]:5300`. A
`/etc/sqns/sqnsd.toml` is picked up automatically if it exists.

`sqnsd --show-pubkey` prints the server's public key, and nothing else, for
scripts.

## Service keys and identities

The key you look up is the **service key**: the one in `sqc://host:port/<key>`,
the one sQUIC pins, the one the node holds and signs its own records with.

Every service key carries a **delegation** from an **identity key** kept
offline. The identity does exactly one job, and it is the job the service key
must not be able to do for itself — retire it:

```
identity key  (offline, in a safe)
      │  issues a delegation over each service key
      ├──────────────┬──────────────┐
      ▼              ▼              ▼
 service key A  service key B  service key C     ← each looked up on its own
      ▼              ▼              ▼
  endpoints      endpoints      endpoints
```

One identity issues as many service keys as it likes. Each resolves
independently under its own public key, and each is rotated or revoked without
touching the others — so three nodes of the same service are three service keys
with three private keys on three hosts, which is the point: no key is ever
copied between machines.

There is deliberately no way to publish without an identity. A key that
answered for itself would be its own authority — and so would whoever stole it:
they could retire it out of your reach, and no server could tell you apart.
Requiring a delegation makes retirement something only a key kept elsewhere can
do. It follows that the identity key has to live somewhere the service host
cannot reach; keep it on the same box and you have the ceremony without the
protection.

## Trust model

A record is signed by the service key it describes — or, to retire that key, by
the identity that issued it. That single property does most of the work:

- A hostile or compromised sqns server **cannot forge** a record, **cannot
  alter** endpoints, and **cannot redirect** a key to an address it controls.
  The only attack available to it is withholding an answer.
- Replication between servers needs no trust between them, because a peer's
  copy carries the original signature.
- Records carry a serial and an expiry, so an old record cannot be replayed
  over a newer one, and a node that disappears stops being advertised on its
  own. A resolver also remembers the newest record it has seen for a key and
  refuses anything older.
- Retiring a key takes its identity, which is not on the machine that holds the
  key. A thief who steals a service key can publish endpoints for it until it is
  retired — but can never retire it, and never forward anyone anywhere.
- A key is bound to its identity by its very first record, and a resolver that
  has seen a key before refuses any later answer claiming a different identity.

Servers inherit sQUIC's own posture: silent to anyone who does not hold the
server's public key, and optionally restricted to a whitelist of client keys.

## Key compromise

| What was stolen | What happens |
|---|---|
| **A service key** | Its identity supersedes it, naming a replacement. Everything signed by the old key is refused from that moment, and lookups of it forward to the new key. Other service keys under the same identity are untouched. |
| **An identity key** | Not recoverable by cryptography: the thief can sign whatever the owner can. Revoke the keys it issued, which fails closed, and re-provision out of band. |
| **An sqns server** | Unchanged. It can withhold an answer, never forge one. |

### Rotating a compromised service key

```bash
# On the machine holding the identity key — no network involved
sqns delegate --identity-key identity.key --service-key service2.key --out d2.bin

# On the replacement node
sqns publish --key-file service2.key --delegation d2.bin -e '203.0.113.9:5300'

# Retire the old key, pointing at the new one
sqns supersede --old-key <old> --new-key <new> --identity-key identity.key
```

A client still holding the old key resolves straight through, and is told its
pinned copy is stale:

```
$ sqns resolve <old>
sqns: <old> has been rotated; it now resolves to <new>
203.0.113.9:5300
```

The thief's next publish is refused:

```
server error Superseded: key <old> was superseded by <new>
```

Retirement is permanent: the tombstone never expires, is never swept, survives a
restart, and replicates like any other record.

### Revoking a key outright

When there is no replacement, revoke instead. Lookups then fail closed rather
than forwarding.

```bash
sqns revoke --key <service key> --identity-key identity.key
sqns revoke --all --identity-key identity.key    # every key this identity issued
```

### What a client cannot check

A client that has *only ever* held a service key, and never resolved it before,
cannot verify which identity issued it — a thief with the stolen private key
could mint a delegation naming an identity of their own. Two things narrow this:

- The server pins the identity from the key's **first** record and refuses any
  later record claiming a different one, which covers every key registered
  before its theft.
- A resolver that has resolved the key before remembers which identity answered
  for it, and refuses any answer that changes it — so the forgery has to reach a
  client that has never seen the real key at all.

Resolution never depends on the identity index.

## Records

| Field | Meaning |
|---|---|
| `key` | the service key this record speaks for — the lookup index |
| `delegation` | the identity that issued this key, and until when |
| `serial` | version counter; the highest serial wins |
| `issued_at` / `ttl` | publication time and lifetime, in seconds |
| body | **live**, **superseded**, or **revoked** |

Each endpoint is a host, a port, a priority and a weight:

| Field | Meaning |
|---|---|
| host | IPv4, IPv6, or a name to resolve |
| port | UDP port |
| priority | tried in ascending order; lower wins |
| weight | breaks ties within a priority, by weighted random draw |

A delegation may be issued with a fixed lifetime (90 days by default, 365 at
most) or with `--never-expires`, for operators who would rather not have a
renewal to forget.

Four states a caller can tell apart:

| State | Meaning |
|---|---|
| no record | the key was never published here |
| withdrawal | a live record with no endpoints: deliberately unreachable, may come back |
| superseded | retired, and forwarding to the key that replaced it |
| revoked | permanently dead, with no replacement |

## Commands

| Command | Purpose |
|---|---|
| `sqns lookup <key>` | full record, or the tombstone and where it forwards to |
| `sqns resolve <key>` | endpoints only, following rotations |
| `sqns publish` | sign and publish an endpoint set |
| `sqns withdraw` | publish an empty record; the key stays alive |
| `sqns delegate` | issue a delegation from an offline identity key |
| `sqns supersede` | retire a key, forwarding to its replacement |
| `sqns revoke` | permanently kill a service key, or all of an identity's |
| `sqns identity <key>` | list the service keys an identity has issued |
| `sqns status` | server counters |
| `sqns keygen` | new keypair |
| `sqnsd` | run a server; SIGINT or SIGTERM writes a final snapshot and exits |
| `sqnsd keygen` | new server identity |

Servers come from `--server` (repeatable) or `$SQNS_SERVER`. Where a server
whitelists clients, pass `--client-key <keyfile>` to connect under a stable key
on the wire — unrelated to the identity keys that issue service keys.

## Replication

Servers replicate by exchanging whole signed records, two ways at once:

- **Push** — a server that accepts a record immediately forwards it to its
  peers, so a publish propagates in one round trip.
- **Pull** — every `sync_interval_secs`, each server asks its peers for
  everything issued since its watermark, which catches up a server that was
  down and seeds a new one.

Both paths land in the same verify-and-merge step, so ordering does not matter
and a record can arrive twice without harm. Retirements travel the same way and
are terminal wherever they land, so retiring a key on one server retires it
across the mesh. Peering is not automatically mutual: list each server on the
other side too.

```toml
# /etc/sqns/sqnsd.toml
listen = "[::]:5300"
key_file = "/etc/sqns/sqnsd.key"
state_file = "/var/lib/sqns/records.db"
peers = ["sqc://ns2.example.com:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5"]
```

See [etc/sqnsd.toml](etc/sqnsd.toml) for every option.

## Upstream resolution

A server answers from its own store. Point it at **upstreams** and a miss
becomes a question rather than a dead end:

```toml
upstreams = ["sqc://ns1.example.com:5300/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5"]
```

That is a different relationship from `peers`. Peering is bidirectional bulk
replication between equals; an upstream is one-way — *ask them if I don't know*
— which is what a leaf near its users needs: resolve the whole network without
mirroring it.

**Relaying adds no trust.** A recursive DNS resolver is an intermediary you have
to believe; here the client verifies the record's own signature, so a relaying
server cannot alter an answer, substitute endpoints, or invent a key. Its only
power stays the one it always had: withholding. A relaying server does check
what it passes on, including one thing its clients cannot — whether the answer
matches the identity that key was first bound to here.

**A leaf stays a leaf.** Relayed answers are cached in memory until they expire,
beside the store and never in it: never offered in `Sync`, never persisted,
never listed under an identity, gone on restart. `sqns status` shows the two
separately:

```
records:   0
upstreams: 1
cached:    1 (relayed, not replicated)
```

Loops terminate because a lookup carries a hop budget: clients send 4, each
forwarding server spends one, and a server with none left answers only for
itself. `sqns lookup --no-recurse` sets it to zero, which answers the operator's
question of whether a server is serving a key or relaying it.

An upstream that cannot be reached is reported as an error, not as "no record" —
an outage and an absence are different answers, and the second one gets cached.

## As a library

```rust
use sqns_client::{Publisher, Resolver};

// Resolve, following any rotation of the key you hold
let resolver = Resolver::single("sqc://ns1.example.com:5300/EFj2…".parse()?)?;
let service = resolver.resolve_service(&"2mTF…".parse()?).await?;
// service.key        — the key actually reached; pin this one
// service.identity   — the identity that issued it
// service.endpoints  — priority order, weighted within each band
if service.is_stale() {
    // the key in your config has been rotated; store service.key instead
}

// Publish under a service key its identity issued. The identity key is never
// in this process.
let publisher = Arc::new(Publisher::new(service_key, delegation, endpoints, 300)?);
tokio::spawn(Arc::clone(&publisher).run(Arc::new(resolver)));
```

`resolve_service` and `resolve` fail closed on a revoked key with
`Error::Revoked`, and follow up to `MAX_SUPERSEDE_HOPS` rotations, erroring on a
cycle rather than spinning. `lookup` hands back the tombstone so a tool can show
it.

## Crates

| Crate | Contents |
|---|---|
| `sqns-core` | records, delegations, retirement, canonical encoding, wire protocol |
| `sqns-client` | resolver, cache, publisher — the embeddable half |
| `sqnsd` | server: store, identity bindings, replication, persistence |
| `sqns` | command line client |

## Wire protocol

One request and one response per sQUIC bidirectional stream, each framed as
`[type:u8][length:u32][payload]`, all integers big-endian. The transport
already authenticates the server and encrypts everything, so the protocol
carries no handshake of its own.

| Request | Response |
|---|---|
| `Lookup { key }` | `Answer { record?, successor? }` |
| `LookupIdentity { identity }` | `Records { records, complete }` |
| `Publish { record }` | `Published { serial, expires_at }` |
| `Status` | `Status { records, peers, uptime, version }` |
| `Sync { since, limit }` | `Records { records, complete }` |

When the answer is a superseded record, `successor` carries the replacement's
own record — one hop, so the caller verifies it against the key the tombstone
named. Longer chains are walked by the client.

A refused `Publish` comes back as an error naming why: `Stale` for a serial that
lost, `BadSignature` for a broken chain, `BadDelegation` for a delegation that
is missing, does not match the key's identity, or has expired, `Superseded` or `Revoked` for
a key that has been retired.

Record encoding is canonical and byte-stable — it is the input to the
signature, which covers the delegation along with everything else. See
[`record.rs`](crates/sqns-core/src/record.rs) for the layout.

## Building

```bash
cargo build --release
cargo test --workspace
```

Binaries land in `target/release/`.

## Deployment

`install.sh --server` does all of this; by hand it is:

```bash
sudo cp target/release/sqns target/release/sqnsd /usr/local/bin/
sudo mkdir -p /etc/sqns /var/lib/sqns
sudo cp etc/sqnsd.toml /etc/sqns/
sudo sqnsd keygen --out /etc/sqns/sqnsd.key
```

Systemd (included as `etc/sqnsd.service`):

```bash
sudo cp etc/sqnsd.service /etc/systemd/system/
sudo systemctl enable --now sqnsd
```

Stopping is clean either way: SIGTERM writes a final snapshot before exiting,
so nothing published since the last periodic write is lost.

## Tests

```bash
cargo test --workspace
```

The suite covers encoding and signature round trips, forgery and rollback
rejection, who may retire a key and who may not, store and snapshot behaviour,
and end-to-end publish, lookup, withdrawal, failover and replication over real
sQUIC connections on loopback — including three services under one identity,
rotation with forwarding, a rotation cycle being refused rather than followed,
and the real binary being stopped with SIGTERM to prove nothing is lost.

## License

MIT
