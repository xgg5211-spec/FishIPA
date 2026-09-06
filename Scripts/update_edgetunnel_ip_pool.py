#!/usr/bin/env python3
"""Build a TLS-verified, EdgeTunnel-compatible Cloudflare IP pool."""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import random
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

IP_SOURCES = {
    4: "https://www.cloudflare.com/ips-v4",
    6: "https://www.cloudflare.com/ips-v6",
}


def load_networks(version: int) -> list[ipaddress._BaseNetwork]:
    request = Request(IP_SOURCES[version], headers={"User-Agent": "FishIPA-EdgeTunnel-Updater/1.0"})
    with urlopen(request, timeout=20) as response:
        text = response.read().decode("utf-8")
    return [ipaddress.ip_network(line.strip()) for line in text.splitlines() if line.strip()]


def sample_addresses(version: int, per_network: int, limit: int, seed: int) -> list[str]:
    randomizer = random.Random(seed + version)
    addresses: list[str] = []
    for network in load_networks(version):
        if version == 4:
            subnets = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [network]
            for subnet in subnets:
                hosts = list(subnet.hosts())
                for _ in range(min(per_network, len(hosts))):
                    addresses.append(str(randomizer.choice(hosts)))
                    if len(addresses) >= limit:
                        return list(dict.fromkeys(addresses))
        else:
            for _ in range(per_network):
                if network.num_addresses <= 2:
                    continue
                value = randomizer.randrange(int(network.network_address) + 1, int(network.broadcast_address))
                addresses.append(str(ipaddress.IPv6Address(value)))
                if len(addresses) >= limit:
                    return list(dict.fromkeys(addresses))
    return list(dict.fromkeys(addresses))


async def tls_probe(address: str, port: int, timeout: float) -> dict | None:
    started = time.perf_counter()
    context = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port,
                ssl=context,
                server_hostname="speed.cloudflare.com",
            ),
            timeout,
        )
        latency = round((time.perf_counter() - started) * 1000, 2)
        writer.close()
        await writer.wait_closed()
        return {
            "ip": address,
            "port": port,
            "latency": latency,
            "ip_version": 6 if ":" in address else 4,
            "probe": "tls",
        }
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None


async def scan(addresses: list[str], port: int, timeout: float, workers: int) -> list[dict]:
    semaphore = asyncio.Semaphore(workers)

    async def limited(address: str) -> dict | None:
        async with semaphore:
            return await tls_probe(address, port, timeout)

    values = await asyncio.gather(*(limited(address) for address in addresses))
    return sorted((value for value in values if value), key=lambda item: item["latency"])


def edge_address(item: dict) -> str:
    host = f"[{item['ip']}]" if item["ip_version"] == 6 else item["ip"]
    return f"{host}:{item['port']}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-per-network", type=int, default=1)
    parser.add_argument("--max-candidates", type=int, default=12000)
    parser.add_argument("--keep", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--output-dir", type=Path, default=Path("data/edgetunnel"))
    args = parser.parse_args()

    seed = int(datetime.now(timezone.utc).strftime("%Y%m%d"))
    ipv4_limit = max(args.max_candidates // 2, 1)
    ipv6_limit = max(args.max_candidates - ipv4_limit, 1)
    ipv4 = sample_addresses(4, args.sample_per_network, ipv4_limit, seed)
    ipv6 = sample_addresses(6, args.sample_per_network, ipv6_limit, seed)
    ipv4_networks = load_networks(4)
    ipv6_networks = load_networks(6)
    candidates = ipv4 + ipv6
    results = asyncio.run(scan(candidates, args.port, args.timeout, args.workers))
    kept = results[: max(args.keep, 1)]
    generated_at = datetime.now(timezone.utc).isoformat()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": generated_at,
        "source": list(IP_SOURCES.values()),
        "probe": "TLS handshake with SNI speed.cloudflare.com",
        "tested": len(candidates),
        "available": len(results),
        "kept": len(kept),
        "results": kept,
    }
    (args.output_dir / "results.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output_dir / "ADD.txt").write_text("\n".join(edge_address(item) for item in kept) + "\n", encoding="utf-8")
    (args.output_dir / "ipv4.txt").write_text("\n".join(edge_address(item) for item in kept if item["ip_version"] == 4) + "\n", encoding="utf-8")
    (args.output_dir / "ipv6.txt").write_text("\n".join(edge_address(item) for item in kept if item["ip_version"] == 6) + "\n", encoding="utf-8")
    (args.output_dir / "source_ipv4.txt").write_text("\n".join(str(network) for network in ipv4_networks) + "\n", encoding="utf-8")
    (args.output_dir / "source_ipv6.txt").write_text("\n".join(str(network) for network in ipv6_networks) + "\n", encoding="utf-8")
    with (args.output_dir / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "port", "latency", "ip_version", "probe"])
        writer.writeheader()
        writer.writerows(kept)

    print(f"TLS tested {len(candidates)} IPs; {len(results)} passed; kept {len(kept)}")


if __name__ == "__main__":
    main()
