#!/usr/bin/env bash
#
# End-to-end drill for sqns: three services under one identity, rotating one
# key with forwarding, revoking another, and a restart to show it all persists.
#
# Everything runs on loopback in a temporary directory and is cleaned up on
# exit. Nothing touches your system.
#
#   ./scripts/demo.sh          # run the whole drill
#   KEEP=1 ./scripts/demo.sh   # leave the server running to poke at yourself
#
set -euo pipefail

PORT="${PORT:-15300}"
KEEP="${KEEP:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$(mktemp -d)"
# Keep the drill out of the real ~/.sqns, whatever the caller has there.
export SQNS_HOME="$DIR/sqns-home"
SQNS="$ROOT/target/debug/sqns"
SQNSD="$ROOT/target/debug/sqnsd"
DAEMON=""

cleanup() {
  [ -n "$DAEMON" ] && kill "$DAEMON" 2>/dev/null || true
  [ -z "$KEEP" ] && rm -rf "$DIR" || true
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
pubkey() { awk '/^public key/ {print $3}'; }

start_daemon() {
  "$SQNSD" --key-file "$DIR/server.key" --listen "127.0.0.1:$PORT" \
    --state-file "$DIR/records.db" >>"$DIR/sqnsd.log" 2>&1 &
  DAEMON=$!
  for _ in $(seq 1 50); do
    "$SQNS" status >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "sqnsd did not come up; see $DIR/sqnsd.log" >&2
  exit 1
}

step "Building"
cargo build --workspace --quiet --manifest-path "$ROOT/Cargo.toml"

step "Starting a server on 127.0.0.1:$PORT"
SERVER=$("$SQNSD" keygen --out "$DIR/server.key" | pubkey)
export SQNS_SERVER="sqc://127.0.0.1:$PORT/$SERVER"
start_daemon
note "SQNS_SERVER=$SQNS_SERVER"

step "One identity, three service keys"
IDENTITY=$("$SQNS" keygen --out "$DIR/identity.key" | pubkey)
note "identity $IDENTITY  (stays offline; used only to issue and retire)"
NS1=$("$SQNS" keygen --out "$DIR/ns1.key" | pubkey)
NS2=$("$SQNS" keygen --out "$DIR/ns2.key" | pubkey)
NS3=$("$SQNS" keygen --out "$DIR/ns3.key" | pubkey)
for n in 1 2 3; do
  "$SQNS" delegate --identity-key "$DIR/identity.key" \
    --service-key "$DIR/ns$n.key" --out "$DIR/d$n.bin" >/dev/null
done
note "node 1  $NS1"
note "node 2  $NS2"
note "node 3  $NS3"

step "Each node publishes for itself, holding only its own key"
for n in 1 2 3; do
  "$SQNS" publish --key-file "$DIR/ns$n.key" --delegation "$DIR/d$n.bin" \
    -e "198.51.100.$n:443" | head -1 || true
done

step "Each resolves under its own public key"
printf '   node 1 -> '; "$SQNS" resolve "$NS1"
printf '   node 2 -> '; "$SQNS" resolve "$NS2"
printf '   node 3 -> '; "$SQNS" resolve "$NS3"

step "What has this identity issued?"
"$SQNS" identity "$IDENTITY"

step "Node 2 is breached: issue a replacement key and rotate to it"
NS2B=$("$SQNS" keygen --out "$DIR/ns2b.key" | pubkey)
"$SQNS" delegate --identity-key "$DIR/identity.key" \
  --service-key "$DIR/ns2b.key" --out "$DIR/d2b.bin" >/dev/null
"$SQNS" publish --key-file "$DIR/ns2b.key" --delegation "$DIR/d2b.bin" \
  -e '203.0.113.9:5300' | head -1 || true
"$SQNS" supersede --old-key "$NS2" --new-key "$NS2B" \
  --identity-key "$DIR/identity.key" | head -2 || true

step "A client that still holds the OLD key reaches the new one"
"$SQNS" resolve "$NS2"

step "The thief still holding node 2's old key tries to republish"
if "$SQNS" publish --key-file "$DIR/ns2.key" --delegation "$DIR/d2.bin" \
     -e '66.66.66.66:443' 2>&1 | tail -1; then
  echo "   UNEXPECTED: the stolen key was accepted" >&2
  exit 1
fi

step "Revoke node 3 outright"
"$SQNS" revoke --key "$NS3" --identity-key "$DIR/identity.key" --yes

step "Node 3 now fails closed, and its siblings are untouched"
"$SQNS" resolve "$NS3" 2>&1 | tail -1 || true
printf '   node 1 -> '; "$SQNS" resolve "$NS1"
printf '   node 2 -> '; "$SQNS" resolve "$NS2B"

step "A leaf server, holding nothing, answers by asking upstream"
# An explicit --key-file must already exist, so make one first.
"$SQNSD" keygen --out "$DIR/leaf.key" >/dev/null
LEAF_KEY=$("$SQNSD" --key-file "$DIR/leaf.key" --show-pubkey 2>/dev/null)
LEAF_ADDR="sqc://127.0.0.1:$((PORT + 1))/$LEAF_KEY"
"$SQNSD" --key-file "$DIR/leaf.key" --listen "127.0.0.1:$((PORT + 1))" \
  --upstream "$SQNS_SERVER" >>"$DIR/leaf.log" 2>&1 &
LEAF=$!
for _ in $(seq 1 50); do
  "$SQNS" --server "$LEAF_ADDR" status >/dev/null 2>&1 && break
  sleep 0.1
done
printf '   via the leaf -> '; "$SQNS" --server "$LEAF_ADDR" resolve "$NS1"
note "$("$SQNS" --server "$LEAF_ADDR" status | tr -s '\n ' ' ')"
note "records 0: the leaf relayed that answer, it did not mirror it"
kill "$LEAF" 2>/dev/null || true
wait "$LEAF" 2>/dev/null || true

step "Restarting the server"
kill "$DAEMON" 2>/dev/null || true
wait "$DAEMON" 2>/dev/null || true
start_daemon
note "$(grep -o 'snapshot loaded.*' "$DIR/sqnsd.log" | tail -1 || true)"

step "Everything survived the restart"
"$SQNS" identity "$IDENTITY"

if [ -n "$KEEP" ]; then
  step "Server left running on 127.0.0.1:$PORT (pid $DAEMON)"
  note "export SQNS_SERVER=$SQNS_SERVER"
  note "keys and state live in $DIR"
  note "stop it with: kill $DAEMON"
  DAEMON=""
else
  step "Done - server stopped, temporary keys removed"
fi
