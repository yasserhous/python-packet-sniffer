import threading
import requests
from scapy.all import *
from scapy.layers.dns import DNS, UDP, DNSQR
from scapy.layers.inet import IP
from collections import defaultdict

#Define a list to store captured packets
captured_packets = []

# Initialize geolocation API details
GEOLOCATION_API_URL = "https://ipinfo.io/"
API_KEY = "6f1fe059694bd6" # Replace with your API key if required

# Initialize a trusted DNS resolver
TRUSTED_DNS = "8.8.8.8"

#DNS tracker
dns_tracker = defaultdict(set)  # Tracks DNS responses for potential spoofing

#DNS Thresholds
DNS_SPOOF_THRESHOLD = 5 #multiple IPs in a single DNS response

def get_geolocation(ip):
    """Fetch geolocation for a given IP address."""
    try:
        response = requests.get(f"{GEOLOCATION_API_URL}{ip}", params={"token": API_KEY})
        response.raise_for_status()
        data = response.json()
        return data.get("city", "Unknown")
    except Exception as e:
        print(f"Geolocation fetch error for {ip}: {e}")
        return "Unknown"

def resolve_with_trusted_dns(domain):
    """Resolve the domain using a trusted DNS resolver."""
    try:
        answer = sr1(IP(dst=TRUSTED_DNS)/UDP()/DNS(rd=1, qd=DNSQR(qname=domain)), verbose=0, timeout=2)
        if answer and answer.haslayer(DNS) and answer[DNS].an:
            trusted_ips = [answer[DNS].an[i].rdata for i in range(answer[DNS].ancount)]
            return trusted_ips
    except Exception as e:
        print(f"Error resolving with trusted DNS: {e}")
    return []
def detect_dns_spoofing(domain,response_ips):
    """
    Output an alert to the console if the geolocation of the response ip is not in the same country as the geolocation of the trusted ip

    """
    #fetching trusted ips
    trusted_ips = resolve_with_trusted_dns(domain)
    trusted_countries = {get_geolocation(ip) for ip in trusted_ips}

    for ip in response_ips:
        ip_country = get_geolocation(ip)
        if ip_country not in trusted_countries:
            print(f"\n[ALERT] DNS spoofing detected for {domain}: {ip} ({ip_country})")

def detect_high_amount_ips(domain):
    if(len(dns_tracker[domain])) > DNS_SPOOF_THRESHOLD:
        print(f"\n[ALERT] Potential DNS spoofing detected for {domain}")

def packet_callback(packet):
    # Append each captured packet to the list
    captured_packets.append(packet)
    if packet.haslayer(DNS) and packet[DNS].qr == 1: #DNS response
        domain = packet[DNS].qd.qname.decode() if packet[DNS].qd else "Unknown"
        response_ips = [packet[DNS].an[i].rdata for i in range(packet[DNS].ancount)]
        dns_tracker[domain].update(response_ips)
        if packet[DNS].ancount > 0:
            answers = []
            for i in range(packet[DNS].ancount):
                try:
                    answer = packet[DNS].an[i].rdata
                    answers.append(answer)
                except AttributeError as e:
                    print(f"Error accessing rdata in DNS answer: {e}")
                    continue
    # Update the tracker with the extracted answers
    dns_tracker[domain].update(answers)
    detect_dns_spoofing(domain,response_ips)
    detect_high_amount_ips(domain)

def sniff_packets():
    #Captures sniff packets indefinitely
    sniff(prn=packet_callback, store=False)

def main():
    output_file = r'C:\Cyber\projects\captured_packets.pcap'
    print("Starting packet sniffer. Packets will be saved to " + output_file)
    print("To save file, please press 'CTRL + C' and terminate the program ")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True  # Ensure the thread exits when the main program exits
    sniff_thread.start()

    try:
        while True:
            pass

    except KeyboardInterrupt:
       # On stopping , write the captured packets to a file
       print(f"\nSaving {len(captured_packets)} packets to '{output_file}'...")
       wrpcap(output_file,captured_packets)
       print("Packets saved successfully")

if __name__ == "__main__":
    main()