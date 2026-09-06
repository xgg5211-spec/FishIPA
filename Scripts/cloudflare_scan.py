#!/usr/bin/env python3
"""Small, headless Cloudflare scanner for the scheduled GitHub Action."""

import argparse
import asyncio
import csv
import ipaddress
import json
import random
import socket
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
    request = Request(IP_SOURCES[version], headers={"User-Agent": "FishIPA-GitHub-Scanner/1.0"})
    with urlopen(request, timeout=20) as response:
        text = response.read().decode("utf-8")
    return [ipaddress.ip_network(line.strip()) for line in text.splitlines() if line.strip()]


def sample_addresses(version: int, per_network: int) -> list[str]:
    addresses: list[str] = []
    networks = load_networks(version)
    for network in networks:
        if version == 4:
            subnets = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [network]
            for subnet in subnets:
                hosts = list(subnet.hosts())
                if hosts:
                    addresses.extend(str(random.choice(hosts)) for _ in range(per_network))
        else:
            for _ in range(per_network):
                value = random.randrange(int(network.network_address) + 1, int(network.broadcast_address))
                addresses.append(str(ipaddress.IPv6Address(value)))
    return list(dict.fromkeys(addresses))


async def probe(address: str, port: int, timeout: float) -> dict | None:
    started = time.perf_counter()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=context, server_hostname="speed.cloudflare.com"),
            timeout,
        )
        latency = round((time.perf_counter() - started) * 1000, 2)
        writer.close()
        await writer.wait_closed()
        return {"ip": address, "latency": latency, "port": port, "ip_version": 6 if ":" in address else 4}
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None


async def scan(addresses: list[str], port: int, timeout: float, workers: int) -> list[dict]:
    semaphore = asyncio.Semaphore(workers)

    async def limited(address: str) -> dict | None:
        async with semaphore:
            return await probe(address, port, timeout)

    values = await asyncio.gather(*(limited(address) for address in addresses))
    return sorted((value for value in values if value), key=lambda item: item["latency"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-per-network", type=int, default=1)
    parser.add_argument("--workers", type=int, default=150)
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--output", type=Path, default=Path("build/results.json"))
    args = parser.parse_args()

    addresses = sample_addresses(4, args.sample_per_network) + sample_addresses(6, args.sample_per_network)
    results = asyncio.run(scan(addresses, args.port, args.timeout, args.workers))
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Cloudflare official IP ranges, sampled using the CloudFlareScan approach",
        "tested": len(addresses),
        "available": len(results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    with args.output.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "latency", "port", "ip_version"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Scanned {len(addresses)} IPs; {len(results)} available")


if __name__ == "__main__":
    main()
