# EdgeTunnel IP pool

This directory is generated daily by GitHub Actions.

- `ADD.txt`: EdgeTunnel-compatible `IP:port` entries, verified with a real TLS handshake. No latency comments are included.
- `results.json`: latency and probe metadata.
- `results.csv`: spreadsheet-friendly report.
- `ipv4.txt` / `ipv6.txt`: verified `IP:port` lists split by address family.
- `source_ipv4.txt` / `source_ipv6.txt`: the current official Cloudflare CIDR ranges used for sampling.

For EdgeTunnel, copy the contents of `ADD.txt` into the admin panel's custom preferred IP list (`ADD.txt` KV entry). EdgeTunnel accepts multiple lines and rotates among them. A raw GitHub URL is provided for inspection and download, but EdgeTunnel's `PROXYIP` variable should receive the actual list or a domain/TXT record, not the URL itself.

To update a deployed EdgeTunnel automatically, add these GitHub repository secrets:

- `EDGETUNNEL_URL`: your deployed Worker or Pages base URL
- `EDGETUNNEL_ADMIN_PASSWORD`: the value of its `ADMIN` variable

The daily workflow fetches the official ranges, performs real TLS handshakes with SNI `speed.cloudflare.com` and only then logs in and POSTs the verified pool to `/admin/ADD.txt`. CIDR ranges are not treated as individually reachable IPs; the workflow samples addresses from each range because scanning every address in Cloudflare's networks is neither practical nor meaningful.
