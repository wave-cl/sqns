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
signed under the authority of the key it is publishing for, and refreshes that
record on a timer; anything holding the key can look it up. The key survives a
compromised host: it is an identity, not a transport key, and what clients dial
can be rotated underneath it.

## Why not DNS

sqns is not a DNS server and speaks no DNS. There are no names, no zones and no
referrals — the lookup key is a 32-byte Ed25519 public key, and an answer comes
from one server or not at all. Answers are signed under that key's own
authority, so verification needs no CA, no DNSSEC chain and no trust in the
server that answered.

| | DNS | sqns |
|---|---|---|
| Lookup key | hierarchical name | Ed25519 public key |
| Answer | records signed by the zone, if DNSSEC | always signed under the key's own authority |
| Trust | resolver chain and CAs | the key you already had |
| Transport | UDP/53, DoT, DoH, DoQ | sQUIC only |
| Server visibility | responds to anyone | silent to anyone without its public key |
| Key compromise | reissue from the CA or zone | rotate the service key under a stable identity |

(sqns does have *delegation*, but it means something else here: an identity key
granting authority to a service key, never one server referring you to
another.)

## Identity keys and service keys

The key you look up is an **identity key**, and it is meant to live offline. It
signs a **delegation** naming the **service key** that the running node holds —
and the service key is what clients pin for the sQUIC handshake and what signs
the records themselves.

```
identity key  (offline, in a safe)
      │  signs a delegation, valid for months
      ▼
service key   (on the host, refreshes records every few minutes)
      ▼
endpoints
```

That split is what makes compromise survivable: stealing the service key does
not let an attacker publish, because publishing needs a delegation only the
identity key can issue. A record with no delegation is signed by its own key and
dialed directly — the simple single-key arrangement, still supported and still
the default for `sqns publish` without `--delegation`.

## Trust model

A record is signed under the authority of the key it describes. That single
property does most of the work:

- A hostile or compromised sqns server **cannot forge** a record, **cannot
  alter** endpoints, and **cannot redirect** a key to an address it controls.
  The only attack available to it is withholding an answer.
- Replication between servers needs no trust between them, because a peer's
  copy carries the original signature.
- Records carry a serial and an expiry, so an old record cannot be replayed
  over a newer one, and a node that disappears stops being advertised on its
  own. Clients also remember the highest authority they have seen for a key and
  refuse anything below it.
- The client verifies every answer against the key it asked for, before the
  answer is used or cached.

Servers inherit sQUIC's own posture: silent to anyone who does not hold the
server's public key, and optionally restricted to a whitelist of client keys.

## Key compromise

| What was stolen | What happens |
|---|---|
| **Service key** | The operator issues a delegation with a higher serial from the offline identity key. Every record signed under the old delegation is refused from that moment — even one with the serial pushed to its maximum. Callers keep resolving the same identity; only the key they dial changes. |
| **Identity key** | Not recoverable by cryptography: the thief can sign whatever the owner can. Revoke the identity, which fails closed, and re-provision a new one out of band. |
| **An sqns server** | Unchanged. It can withhold an answer, never forge one. |

### Rotating a compromised service key

```bash
# On the machine holding the identity key — no network involved
sqns delegate --identity-key identity.key --service-key service2.key \
  --serial 2 --out d2.bin

# On the node, with the new service key and the new delegation
sqns publish --key-file service2.key --delegation d2.bin -e '203.0.113.9:5300'
```

The thief's next publish is refused:

```
server error BadDelegation: <identity> has delegation 2;
this record was signed under 1
```

The retired delegation stays retired: servers remember the highest delegation
serial for a key even after the records under it expire, and that mark is
written to the snapshot. A peer learns of a rotation from the records it
replicates, so rotate while the node is publishing normally.

### Revoking an identity

Revocation is **permanent and irreversible**. Once a server holds the
tombstone, no record for that key is ever accepted again, at any serial; the
tombstone never expires and is never swept.

```bash
sqns revoke --key-file identity.key --reason "host compromised" \
  --successor <new identity>
```

A revocation may name a successor, but it is only a hint: whoever stole the key
could have written it. Clients surface it and never follow it — confirm any
successor out of band before trusting it.

## Records

| Field | Meaning |
|---|---|
| `key` | the identity key this record speaks for |
| `serial` | version counter; the highest serial wins within a delegation |
| `issued_at` / `ttl` | publication time and lifetime, in seconds |
| body | either **live** — an optional delegation plus endpoints — or **revoked** |

A live record's delegation carries the service key, its own monotonic serial,
and an expiry. Ordering is by `(delegation serial, record serial, issued_at)`,
so a new delegation outranks everything published under an older one.

Each endpoint is a host, a port, a priority and a weight:

| Field | Meaning |
|---|---|
| host | IPv4, IPv6, or a name to resolve |
| port | UDP port |
| priority | tried in ascending order; lower wins |
| weight | breaks ties within a priority, by weighted random draw |

A live record with **no endpoints is a withdrawal** — the key is deliberately
unreachable for now. Three states a caller can tell apart:

| State | Meaning |
|---|---|
| no record | the key was never published here |
| withdrawal | published, deliberately unreachable, may come back |
| revocation | the identity is permanently dead and will never return |

## Install

```bash
cargo install --path crates/sqnsd   # server
cargo install --path crates/sqns    # client
```

## Quick start

Generate the server's identity and start it:

```bash
sqnsd keygen --out sqnsd.key
sqnsd --key-file sqnsd.key --listen 0.0.0.0:5300 --state-file records.db
```

It prints the connection string clients need:

```
connection string: sqc://0.0.0.0:5300/3LGScP5aB7t9tNuFzYwxY8EK6fZ2TNZqQx2o5jgxsNgj
```

Publish a node's endpoints, signed by the node's own key:

```bash
export SQNS_SERVER=sqc://ns1.example.com:5300/3LGScP5aB7t9tNuFzYwxY8EK6fZ2TNZqQx2o5jgxsNgj

sqns keygen --out node.key
sqns publish --key-file node.key \
  -e '198.51.100.4:443,priority=10,weight=100' \
  -e '[2001:db8::5]:443,priority=10,weight=1' \
  -e 'backup.example.com:4433,priority=50'
```

Look it up from anywhere:

```bash
sqns lookup 2mTFsr7ozzywfcCzRENivZcWiFPpbbuejGXe61oRX1eu
sqns resolve 2mTFsr7ozzywfcCzRENivZcWiFPpbbuejGXe61oRX1eu   # endpoints only
```

That publishes under a single key, which is the simplest thing that works. For
anything you would mind losing, put the identity key offline and delegate to a
service key instead — see [Key compromise](#key-compromise):

```bash
sqns delegate --identity-key identity.key --service-key service.key \
  --serial 1 --out d1.bin                       # where the identity key lives
sqns publish --key-file service.key --delegation d1.bin -e '198.51.100.4:443'
```

A long-running node should hold its record open, which republishes inside the
TTL and withdraws the key on exit:

```bash
sqns publish --key-file node.key -e '198.51.100.4:443' --ttl 300 --keepalive
```

## Commands

| Command | Purpose |
|---|---|
| `sqns lookup <key>` | full record: serial, expiry, key to dial, endpoints — or the tombstone |
| `sqns resolve <key>` | endpoints only, in the order to try them |
| `sqns publish` | sign and publish an endpoint set |
| `sqns withdraw` | publish an empty record |
| `sqns delegate` | issue a delegation from an offline identity key (raise `--serial` to rotate) |
| `sqns revoke` | permanently kill an identity |
| `sqns status` | server counters |
| `sqns keygen` | new keypair |
| `sqnsd` | run a server |
| `sqnsd keygen` | new server identity |

Servers come from `--server` (repeatable) or `$SQNS_SERVER`. Where a server
whitelists clients, pass `--identity <keyfile>` to connect under a stable key.

## Replication

Servers replicate by exchanging whole signed records, two ways at once:

- **Push** — a server that accepts a record immediately forwards it to its
  peers, so a publish propagates in one round trip.
- **Pull** — every `sync_interval_secs`, each server asks its peers for
  everything issued since its watermark, which catches up a server that was
  down and seeds a new one.

Both paths land in the same verify-and-merge step, so ordering does not matter
and a record can arrive twice without harm. Revocations travel the same way and
are terminal wherever they land, so killing an identity on one server kills it
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

## As a library

```rust
use sqns_client::{Publisher, Resolver};

// Resolve: endpoints, plus the key to pin when dialing them
let resolver = Resolver::single("sqc://ns1.example.com:5300/EFj2…".parse()?)?;
let service = resolver.resolve_service(&"2mTF…".parse()?).await?;
// service.identity     — stable across rotations
// service.service_key  — what to pin for the sQUIC handshake
// service.endpoints    — priority order, weighted within each band

// Publish under a delegation, and keep the record alive. The identity key is
// never in this process.
let publisher = Arc::new(Publisher::delegated(
    identity, service_key, delegation, endpoints, 300,
)?);
tokio::spawn(Arc::clone(&publisher).run(Arc::new(resolver)));
```

`resolve_service` and `resolve` fail closed on a revoked key with
`Error::Revoked`; `lookup` hands back the tombstone so a tool can show it.

## Crates

| Crate | Contents |
|---|---|
| `sqns-core` | records, delegations, revocations, canonical encoding, wire protocol |
| `sqns-client` | resolver, cache, publisher — the embeddable half |
| `sqnsd` | server: store, replication, revocation state, persistence |
| `sqns` | command line client |

## Wire protocol

One request and one response per sQUIC bidirectional stream, each framed as
`[type:u8][length:u32][payload]`, all integers big-endian. The transport
already authenticates the server and encrypts everything, so the protocol
carries no handshake of its own.

| Request | Response |
|---|---|
| `Lookup { key }` | `Answer { record? }` |
| `Publish { record }` | `Published { serial, expires_at }` |
| `Status` | `Status { records, peers, uptime, version }` |
| `Sync { since, limit }` | `Records { records, complete }` |

A refused `Publish` comes back as an error naming why: `Stale` for a serial
that lost, `BadSignature` for a broken chain, `BadDelegation` for authority
that has been retired or has expired, `Revoked` for a key that is dead.

Record encoding is canonical and byte-stable — it is the input to the
signature, which covers the delegation along with everything else. See
[`record.rs`](crates/sqns-core/src/record.rs) for the layout.

## Tests

```bash
cargo test --workspace
```

The suite covers encoding and signature round trips, forgery and rollback
rejection, delegation and revocation rules, store and snapshot behaviour, and
end-to-end publish, lookup, withdrawal, failover and replication over real sQUIC
connections on loopback — including a full compromise drill: publish under one
delegation, rotate to a new service key, and assert the old one is locked out.

## License

MIT
