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
signed by the very key it is publishing for, and refreshes that record on a
timer; anything holding the key can look it up.

## Why not DNS

sqns is not a DNS server and speaks no DNS. There are no names, no zones and no
delegation — the lookup key is a 32-byte Ed25519 public key, the same one sQUIC
already pins. Answers are signed by that key, so verification needs no CA, no
DNSSEC chain and no trust in the server that answered.

| | DNS | sqns |
|---|---|---|
| Lookup key | hierarchical name | Ed25519 public key |
| Answer | records signed by the zone, if DNSSEC | always signed by the key itself |
| Trust | resolver chain and CAs | the key you already had |
| Transport | UDP/53, DoT, DoH, DoQ | sQUIC only |
| Server visibility | responds to anyone | silent to anyone without its public key |

## Trust model

A record is signed by the key it describes. That single property does most of
the work:

- A hostile or compromised sqns server **cannot forge** a record, **cannot
  alter** endpoints, and **cannot redirect** a key to an address it controls.
  The only attack available to it is withholding an answer.
- Replication between servers needs no trust between them, because a peer's
  copy carries the original signature.
- Records carry a serial and an expiry, so an old record cannot be replayed
  over a newer one, and a node that disappears stops being advertised on its
  own.
- The client verifies every answer against the key it asked for, before the
  answer is used or cached.

Servers inherit sQUIC's own posture: silent to anyone who does not hold the
server's public key, and optionally restricted to a whitelist of client keys.

## Records

| Field | Meaning |
|---|---|
| `key` | the Ed25519 public key this record speaks for |
| `serial` | version counter; the highest serial wins |
| `issued_at` / `ttl` | publication time and lifetime, in seconds |
| `endpoints` | where the key can be reached |

Each endpoint is a host, a port, a priority and a weight:

| Field | Meaning |
|---|---|
| host | IPv4, IPv6, or a name to resolve |
| port | UDP port |
| priority | tried in ascending order; lower wins |
| weight | breaks ties within a priority, by weighted random draw |

A record with **no endpoints is a withdrawal** — the key is deliberately
unreachable, which a caller can tell apart from a key that was never published.

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

A long-running node should hold its record open, which republishes inside the
TTL and withdraws the key on exit:

```bash
sqns publish --key-file node.key -e '198.51.100.4:443' --ttl 300 --keepalive
```

## Commands

| Command | Purpose |
|---|---|
| `sqns lookup <key>` | full record: serial, expiry, endpoints |
| `sqns resolve <key>` | endpoints only, in the order to try them |
| `sqns publish` | sign and publish an endpoint set |
| `sqns withdraw` | publish an empty record |
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
and a record can arrive twice without harm. Peering is not automatically
mutual: list each server on the other side too.

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

// Resolve
let resolver = Resolver::single("sqc://ns1.example.com:5300/EFj2…".parse()?)?;
for endpoint in resolver.resolve(&"2mTF…".parse()?).await? {
    // endpoints arrive in priority order, weighted within each band
}

// Publish, and keep the record alive
let publisher = Arc::new(Publisher::new(signing_key, endpoints, 300));
tokio::spawn(Arc::clone(&publisher).run(Arc::new(resolver)));
```

## Crates

| Crate | Contents |
|---|---|
| `sqns-core` | records, canonical encoding, signatures, wire protocol |
| `sqns-client` | resolver, cache, publisher — the embeddable half |
| `sqnsd` | server: store, replication, persistence |
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

Record encoding is canonical and byte-stable — it is the input to the
signature. See [`record.rs`](crates/sqns-core/src/record.rs) for the layout.

## Tests

```bash
cargo test --workspace
```

The suite covers encoding and signature round trips, forgery and rollback
rejection, store and snapshot behaviour, and end-to-end publish, lookup,
withdrawal, failover and replication over real sQUIC connections on loopback.

## License

MIT
