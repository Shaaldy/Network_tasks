import requests as requests
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1


def tracert(target_ip):
    as_info = []
    ttl = 1
    while True:
        packet = IP(dst=target_ip, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=1)
        if reply is None or reply.src == target_ip or ttl > 30:
            break

        response = requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={reply.src}")
        data = response.json()
        as_info.append((ttl, reply.src, get_asn(data), get_provider(data)))
        ttl += 1
    return as_info


def get_asn(data):
    asn = data["data"]["asns"][0]["asn"] if data["data"]["asns"] else "Unknown"
    return asn


def get_provider(data):
    provider = data["data"]["asns"][0]["holder"] if data["data"]["asns"] else ''
    return provider


if __name__ == "__main__":
    target_ip = 'google.com'
    as_table = tracert(target_ip)

    print("TTL  | IP Address       |   ASN   |     Provider")
    print("-" * 83)
    for ttl, ip, asn, provider in as_table:
        print(f"{ttl:<4} | {ip:<16} | {asn:<7} | {provider}")