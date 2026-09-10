# VOID Node Agent v2

Lightweight IP-blocking and diagnostics agent for Remnawave/Xray nodes. It is
installed as a hardened systemd service and normally uses 30–50 MB RAM.

## Security model

- no public management port: the local API binds to `127.0.0.1` only;
- the node initiates an HTTPS connection to the central VOID service;
- installation uses a single-use code with a 1–60 minute lifetime;
- every node receives a separate 384-bit random token;
- the central database stores only its SHA-256 hash;
- a replacement enrollment immediately invalidates the previous token;
- remote actions are an explicit allow-list, not a shell;
- the service runs as dedicated user `voidnode`, not root;
- the systemd sandbox denies privilege escalation and grants only `CAP_NET_ADMIN`/`CAP_NET_RAW`;
- the Docker socket is inaccessible to the agent;
- block state and identity are atomically stored with root-only permissions.

The public repository contains no node token, registration secret, database
credential, private key, or infrastructure allow-list.

## Install

Generate a one-time command in the VOID admin panel or with:

```text
/nodecode 10
```

Then run the generated command on the node. Its shape is:

The panel returns one HTTPS bootstrap command. The node name is generated from
its hostname and machine identity, so it does not need to be entered manually.

The code is consumed once and is never saved to disk. To migrate an existing
node, simply issue another one-time code in the panel or use:

```text
/nodecode 10
```

After successful enrollment the installer removes the previous VOID agent
state, its old public-port rule and its dedicated firewall chains. Remnawave,
Docker, Xray and unrelated firewall rules are not changed.

## Clean removal

The private admin panel also shows a pinned removal command. It deletes only
`void-node-agent`, `/var/lib/void-node-agent` and firewall objects created by
this project. Installed system packages are intentionally kept because other
services may use them.

## What central management can do

- apply/synchronize IP blocks;
- remove IP blocks;
- health check;
- bounded Telegram connectivity diagnostics;
- revoke or rotate a node identity.

## Network audit

The control plane can request one of two fixed diagnostics; it cannot provide
shell commands, URLs, proxy settings or arbitrary test arguments.

- **Quick audit** checks the public IPv4, DNS/HTTPS reachability of ChatGPT,
  Gemini, OpenAI, Google AI and YouTube, plus CPU steal, load, RAM and disk.
  It is suitable for a scheduled run.
- **Full Geo audit** adds the checksum-pinned `geocheck` binary. Its compact
  report includes IP reputation, region consensus, service availability and
  route findings. It is intended for manual checks or infrequent runs.

Automatic audits are off by default. The VOID panel can enable a quick audit
once per day, once per three days, or once per week. The scheduler releases no
more than two nodes per minute and stores its state/results in the central
database, so restarts do not create a burst or duplicate alerts.

`dpi-detector`, YABS, iperf and CPU benchmarks are intentionally not part of
the automatic audit: they can consume a node's bandwidth/CPU and, when run on
a foreign VPS, do not measure a Russian subscriber's ISP filtering.

There is deliberately no arbitrary command execution. Full administration and
software deployment stay on a separate SSH key channel. This prevents a panel
bug from becoming unrestricted root access to every VPN node.

## Local operations

```bash
journalctl -u void-node-agent -f
systemctl status void-node-agent
sudo bash update.sh
ipset list void-block
iptables -L VOID-BLOCK -n --line-numbers
```

`update.sh` preserves `/var/lib/void-node-agent/identity.json` and
`/var/lib/void-node-agent/state.json`.

The VOID admin panel can also produce a pinned update command. It downloads
one immutable release and runs only `update.sh`; it does not require a new
enrollment code and does not change the node identity, block state, Remnawave,
Docker or Xray.

## Remnawave

Remnawave Node remains in its own Docker container. This agent is a small host
systemd service because it manages the host firewall. It does not modify the
Remnawave compose stack and does not expose Docker or the Remnawave API.
