import requests as requests
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1


def tracert(target_ip):
    ttl = 1
    while True:
        packet = IP(dst=target_ip, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=1)
        if reply is None or reply.src == target_ip or ttl > 30:
            break
        ip_address = reply.src
        response = requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_address}")
        data = response.json()
        asn = data["data"]["asns"][0]["asn"] if data["data"]["asns"] else "Unknown"
        provider = data["data"]["asns"][0]["holder"] if data["data"]["asns"] else "Unknown"
        country = get_country(reply.src)
        yield ttl, ip_address, asn, provider, country
        ttl += 1


def get_country(ip_address):
    response_country = requests.get(f"https://stat.ripe.net/data/rir/data.json?resource={ip_address}&lod=2")
    data = response_country.json()
    for rir in data.get("data", {}).get("rirs", []):
        if isinstance(rir, dict) and rir.get("country"):
            return rir["country"]


if __name__ == "__main__":
    target_ip = 'hltv.org' # сюда писать IP или доменное имя
    as_generator = tracert(target_ip)

    print("TTL  | IP Address       |   ASN   |          Provider                | Country")
    print("-" * 83)
    for ttl, ip, asn, provider, country in as_generator:
        print(f"{ttl:<4} | {ip:<16} | {asn:<7} | {provider:<32} | {country}")
