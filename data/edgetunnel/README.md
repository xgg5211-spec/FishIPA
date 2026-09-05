# EdgeTunnel IP pool

This directory is generated daily by GitHub Actions.

- `ADD.txt`: EdgeTunnel-compatible `IP:port#remark` entries, verified with a real TLS handshake.
- `results.json`: latency and probe metadata.
- `results.csv`: spreadsheet-friendly report.
- `ipv4.txt` / `ipv6.txt`: address-only lists.

For EdgeTunnel, copy the contents of `ADD.txt` into the admin panel's custom preferred IP list (`ADD.txt` KV entry). EdgeTunnel accepts multiple lines and rotates among them. A raw GitHub URL is provided for inspection and download, but EdgeTunnel's `PROXYIP` variable should receive the actual list or a domain/TXT record, not the URL itself.
