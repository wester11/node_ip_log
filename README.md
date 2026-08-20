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
- the systemd sandbox denies privilege escalation and limits Linux capabilities;
- block state and identity are atomically stored with root-only permissions.

The public repository contains no node token, registration secret, database
credential, private key, or infrastructure allow-list.

## Install

Generate a one-time command in the VOID admin panel or with:

```text
/nodecode finland-1 10
```

Then run the generated command on the node. Its shape is:

```bash
git clone https://github.com/wester11/node_ip_log.git && cd node_ip_log && \
sudo env CENTRAL_API_URL='https://netvoid.ru' NODE_NAME='finland-1' \
VOID_NODE_ENROLLMENT_CODE='vne1_...' bash install.sh
```

The code is consumed once and is never saved to disk. To migrate an existing
node, issue a replacement code in the panel or use:

```text
/nodecode finland-1 10 replace
```

## What central management can do

- apply/synchronize IP blocks;
- remove IP blocks;
- health check;
- bounded Telegram connectivity diagnostics;
- revoke or rotate a node identity.

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

## Remnawave

Remnawave Node remains in its own Docker container. This agent is a small host
systemd service because it manages the host firewall. It does not modify the
Remnawave compose stack and does not expose Docker or the Remnawave API.
