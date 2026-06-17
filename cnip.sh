#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
MIN_CN_IPV4_COUNT=8000
LIST_NAME="CN"
EXTRA_CIDR="10.10.0.0/16"

apnic_file="$(mktemp)"
output_file="$(mktemp)"

cleanup() {
  rm -f "$apnic_file" "$output_file"
}
trap cleanup EXIT

wget -q -O "$apnic_file" "$APNIC_URL"

python3 - "$apnic_file" "$output_file" "$MIN_CN_IPV4_COUNT" "$LIST_NAME" "$EXTRA_CIDR" <<'PY'
import ipaddress
import sys

apnic_path, output_path, min_count, list_name, extra_cidr = sys.argv[1:]
min_count = int(min_count)
records = []

with open(apnic_path, "r", encoding="utf-8") as source:
    for line_number, line in enumerate(source, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("|")
        if len(parts) < 7:
            continue

        _, country_code, record_type, start, value, _, status = parts[:7]
        if country_code != "CN" or record_type != "ipv4":
            continue
        if status not in {"allocated", "assigned"}:
            raise SystemExit(f"unsupported APNIC status at line {line_number}: {status}")

        try:
            address_count = int(value)
            start_ip = ipaddress.IPv4Address(start)
        except ValueError as exc:
            raise SystemExit(f"invalid APNIC IPv4 record at line {line_number}: {exc}") from exc

        if address_count <= 0 or address_count & (address_count - 1):
            raise SystemExit(f"invalid APNIC IPv4 address count at line {line_number}: {address_count}")

        prefix_length = 32 - (address_count.bit_length() - 1)
        try:
            network = ipaddress.ip_network(f"{start_ip}/{prefix_length}", strict=True)
        except ValueError as exc:
            raise SystemExit(f"invalid APNIC CIDR at line {line_number}: {exc}") from exc

        records.append(network)

if len(records) < min_count:
    raise SystemExit(f"CN IPv4 record count too small: {len(records)}")

try:
    extra_network = ipaddress.ip_network(extra_cidr, strict=True)
except ValueError as exc:
    raise SystemExit(f"invalid extra CIDR {extra_cidr}: {exc}") from exc

with open(output_path, "w", encoding="utf-8") as output:
    output.write(f"/ip firewall address-list remove [/ip firewall address-list find list={list_name}]\n")
    output.write("/ip firewall address-list\n")
    for network in records:
        output.write(f"add address={network.with_prefixlen} disabled=no list={list_name}\n")
    output.write(f"add address={extra_network.with_prefixlen} disabled=no list={list_name}\n")
PY

mv "$output_file" "$SCRIPT_DIR/cnip.rsc"
