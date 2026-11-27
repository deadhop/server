---
name: deadhop-server-operate
description: "Configure and operate the deadhop payment service, the self-hosted on-chain bitcoin payment server that opens no port and talks over Nostr relays. Use it whenever someone wants to set up, configure, harden, hide or troubleshoot deadhop: choosing a setup, connecting their Electrum server (Fulcrum, electrs) and pinning its certificate with `deadhop fingerprint`, picking their own xpub/zpub or a generated wallet, setting DEADHOP_ADMINS, public invoicing, routing relays through Tor or a proxy, the production checklist, the `deadhop` commands, or when invoices do not show as paid, the service will not start, or the first address does not match their wallet."
license: MIT
metadata:
  repository: https://github.com/deadhop/server
---

# Operate the deadhop payment service

deadhop runs next to the operator's bitcoin node. It issues invoices, watches the chain
through an Electrum server and reports payments. It never listens on a port: customers and
operators reach it only through Nostr relays (ContextVM, MCP over Nostr). It holds only a
watch-only account key, so it cannot spend what it receives.

Every page of the docs has a Markdown twin. Fetch the `.md` page for details instead of
guessing a setting: `https://deadhop.run/docs/<page>.md`.

## Safety rules

- **Release goods only on `confirmed`.** `detected` means the full amount was seen, not that
  it is final: an unconfirmed payment can still be replaced or double-spent. A shop's backend
  must check every invoice itself with `getInvoice(id)` (`@deadhop/client`) before it ships,
  because callbacks such as `onPaid` run in the customer's browser. An `expired` invoice can
  still become `confirmed` from a late payment (watched for `DEADHOP_LATE_GRACE_SECS`).
- **Never handle the recovery phrase.** With a generated wallet, the user runs
  `deadhop wallet export` in their own terminal and writes the 24 words on paper. Do not run it
  yourself, do not ask for the words, and never paste them into chat, a file or an issue:
  anyone who has them can spend the funds.
- **Never ask for or handle an `nsec`.** Operators sign in to the dashboard with a NIP-07
  browser extension, using a key made only for this service. `DEADHOP_ADMINS` takes public
  keys only (hex, `npub1…` or `nprofile`).
- **Check the first address before real money.** The service logs the receive address at
  index 0 on start. The user's wallet must list that exact address. A wrong key type (BIP-49
  or Taproot instead of BIP-84) still produces valid addresses the wallet never shows.
- **Keep the Electrum server private**: on the same machine or a private network, never the
  internet. Whoever runs it, or can tamper with the link, decides which invoices look paid.

## 1. Choose a setup with the user

Ask three questions; each answer picks a guide ([install.md](https://deadhop.run/docs/install.md),
ten worked combinations in [setups.md](https://deadhop.run/docs/setups.md)):

1. **How it runs:** Docker Compose from [deadhop/stack](https://github.com/deadhop/stack)
   (recommended, [deploy-compose.md](https://deadhop.run/docs/deploy-compose.md)) or one binary
   under systemd ([deploy-systemd.md](https://deadhop.run/docs/deploy-systemd.md)). There are no
   published images or binaries yet; both build from source.
2. **Where payments land:**
   - *Their own wallet*: set `DEADHOP_XPUB` to the wallet's BIP-84 **account** key (`xpub…`/`zpub6…`,
     or `tpub`/`vpub` on test networks). Nothing on the server can spend. Per-wallet steps:
     [xpub/index.md](https://deadhop.run/docs/xpub/index.md).
   - *A generated wallet* (Compose only): leave `DEADHOP_XPUB` unset; the `wallet` container,
     with no network, makes one. Meant for small balances.
   - *Generated, then swept* to a cold wallet by the sweeper:
     [wallet/sweep.md](https://deadhop.run/docs/wallet/sweep.md).
3. **Who creates invoices:** only operators (the default), the shop's backend with its own
   operator key ([integrate-backend.md](https://deadhop.run/docs/integrate-backend.md)), or anyone
   with proof of work (`DEADHOP_PUBLIC_INVOICING=true`, [integrate.md](https://deadhop.run/docs/integrate.md)).

Decide the wallet key before the first start: a database that has handed out addresses
refuses a different `DEADHOP_XPUB` ("this database was used with a different wallet key").

## 2. Required settings

All configuration is environment variables; the full table is
[configuration.md](https://deadhop.run/docs/configuration.md).

```sh
DEADHOP_RELAYS=wss://relay.one.example,wss://relay.two.example   # required for the binary; Compose has a default
DEADHOP_ELECTRUM=tls://node.lan:50002          # or host:port (plain TCP) on the same machine
DEADHOP_ELECTRUM_CERT_SHA256=<fingerprint>     # pin for tls://
DEADHOP_ADMINS=npub1…                          # operators; or DEADHOP_PUBLIC_INVOICING=true, at least one
DEADHOP_XPUB=zpub6…                            # optional with Compose (unset: generated wallet)
DEADHOP_NETWORK=bitcoin                        # default; testnet, signet or regtest
```

**Never set up yet?** Started with none of `DEADHOP_ELECTRUM`, `DEADHOP_ADMINS` and
`DEADHOP_PUBLIC_INVOICING` and no database in its data directory, the service does not exit:
it waits idle in *setup mode*, connected to nothing, lists what is missing in its log and
writes `setup.json` (setting names, never values) to `DEADHOP_PUBLIC_DIR`. The dashboard then
offers a setup page that ends with the settings to paste. Restart the service once they are set.

**Electrum across a network: pin the certificate.**

```sh
deadhop fingerprint node.lan:50002
# Compose: docker compose run --rm --no-deps deadhop fingerprint node.lan:50002
```

It prints the SHA-256 fingerprint and the two lines to set. It trusts whatever answered, so
have the user compare it on the node, for example
`openssl x509 -in <fulcrum cert.pem> -noout -fingerprint -sha256`. List two fingerprints,
comma-separated, while rotating a certificate. A server with no TLS port works over plain TCP
on a trusted network, with a warning on every start. Inside a container `127.0.0.1` is the
container itself: use the host's LAN address. Details: [electrum.md](https://deadhop.run/docs/electrum.md).

Useful optional settings: `DEADHOP_MIN_CONFIRMATIONS` (default 1; raise it for larger
amounts), `DEADHOP_POW_BITS` (default 20; keep at least 20 with public invoicing),
`DEADHOP_NAME`, `DEADHOP_DATA_DIR` (default `data`; holds the database and the service's keys).
Operators can change relays, limits, confirmations and the proxy from the dashboard; those
overrides live in the database. `DEADHOP_XPUB`, `DEADHOP_NETWORK`, `DEADHOP_ELECTRUM`,
`DEADHOP_DATA_DIR`, `DEADHOP_ANNOUNCE` and the keys in `DEADHOP_ADMINS` stay host-only.

## 3. Hide where it runs (if it matters)

Relays see the IP address the service connects from. To hide it, route relay traffic (and
only relay traffic) through Tor or a VPN, **before the first start**:

```sh
DEADHOP_PROXY=socks5://127.0.0.1:9050     # Compose: socks5://tor:9050 with a Tor container
DEADHOP_PROXY_LOCKED=true                 # an operator key cannot change the proxy from the dashboard
DEADHOP_PROXY_OFFLINE=kill_switch         # default: no proxy reachable, no relay connections
```

`.onion` relays work through a SOCKS proxy. `DEADHOP_TRANSPARENT_PROXY=true` is for hosts that
already route everything through Tor or a VPN; the service cannot check that claim. The
Electrum server is always reached directly. Groups, rotation and per-relay rules:
[hide.md](https://deadhop.run/docs/hide.md). Check the privacy score on the dashboard's Overview.

## 4. Commands

| Command | What it does |
| --- | --- |
| `deadhop` | Run the service, configured by `DEADHOP_*` variables |
| `deadhop pubkey` | Print the public invoices key (hex), the one apps and customers use; creates the keys if needed |
| `deadhop pubkey admin` | Print the administration key (hex); never announced |
| `deadhop pubkey ID` | Print the public key of an invoice key added from the dashboard (one per service), such as `shop`; prints nothing for an id the service has not made |
| `deadhop fingerprint HOST:PORT` | Print an Electrum server's TLS certificate fingerprint and the settings that pin it |
| `deadhop wallet serve` | The offline wallet service: generate a wallet on first start, write its account key to `DEADHOP_XPUB_FILE` |
| `deadhop wallet export` | Print the generated wallet's 24 words. Refused with your own `DEADHOP_XPUB`. **User only** |

Anything else prints the usage and exits with status 2. With Compose, prefix
`docker compose run --rm --no-deps deadhop …` (or `docker compose exec wallet deadhop wallet export`).
See [cli.md](https://deadhop.run/docs/cli.md).

## 5. Verify it works

1. The log shows `deadhop is serving pubkey=… network=… relays=… via_proxy=…` and
   `first receive address (index 0): check that your wallet lists it address=bc1q…`.
2. The user compares that address with their wallet's first receive address (for a generated
   wallet: watch the account key the export printed, in Sparrow as an xPub / Watch Only
   wallet). Stop if they differ.
3. The dashboard's Overview shows the chain height under **Chain**, the relays and the proxy.
4. Raise the wallet's gap limit to at least the dashboard's **addresses created** plus 20:
   every invoice uses a new address, paid or not ([watch-only.md](https://deadhop.run/docs/watch-only.md)).
5. Walk the [production checklist](https://deadhop.run/docs/deployment.md) with the user before
   the first real payment: backups of the data directory with permissions intact (and
   `<data dir>/backups` copied off the host), a supervisor, inbound traffic dropped, two or
   more `wss://` relays, the dashboard over HTTPS, someone watching `chain_ok` and `watch_errors`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Logs "deadhop is not set up yet" and stays idle | Setup mode: none of the required settings is set and there is no database; set them and restart |
| Exits with `… is required`, or "set DEADHOP_ADMINS and/or DEADHOP_PUBLIC_INVOICING=true" | Only some required settings are set, or a service with a database lost them; under Compose it restarts until set |
| Exits with "server is on a different chain" | `DEADHOP_NETWORK` does not match the Electrum server's chain |
| Refuses to start over the certificate | The pin does not match: re-read with `deadhop fingerprint` and compare on the node |
| "this database was used with a different wallet key" | `DEADHOP_XPUB` changed; switch back, or start the new key with a fresh data directory |
| Refuses a key file | A file in the data directory is readable by others; restore owner-only permissions |
| Payments missing in the wallet | Gap limit too low, or a non-BIP-84 key: compare the first address |
| Warning "DEADHOP_ELECTRUM is not on this machine" | Plain TCP to another host; prefer `tls://` with a pin |
| No relay connects behind a proxy | `kill_switch` while the proxy is down (Tor needs a minute on first start) |
| Guest sees "public invoicing is switched off" | Expected default; add their key to `DEADHOP_ADMINS` or enable public invoicing |

Invoice states and the protocol: [how-it-works.md](https://deadhop.run/docs/how-it-works.md),
tools: [api.md](https://deadhop.run/docs/api.md), threats: [security.md](https://deadhop.run/docs/security.md).
