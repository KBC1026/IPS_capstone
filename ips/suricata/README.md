# Suricata IPS Runtime Layout

Canonical repo-managed files:

- `ips/suricata/suricata.yaml`
- `ips/suricata/local.rules`

The systemd override in `ips/systemd/suricata.service.d/override.conf` makes
`suricata.service` load the repo-managed yaml directly. The yaml keeps the
downloaded `suricata.rules` under `/var/lib/suricata/rules`, but loads
`local.rules` from this repo by absolute path.

Apply runtime deployment as root:

```sh
install -D -m 0644 ips/systemd/suricata.service.d/override.conf /etc/systemd/system/suricata.service.d/override.conf
systemctl daemon-reload
suricata -T -c /home/kbc/ips-security_capstone_projects/ips/suricata/suricata.yaml
systemctl restart suricata
systemctl status suricata --no-pager
```

After restart, verify logs:

```sh
test -s /var/log/suricata/fast.log
test -s /var/log/suricata/eve.json
```
