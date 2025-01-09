import threading
from scapy.all import  sniff, wrpcap
from scapy.layers.dns import DNS,UDP
from collections import defaultdict
#Define a list to store captured packets
captured_packets = []

#DNS tracker
dns_tracker = defaultdict(set)  # Tracks DNS responses for potential spoofing

#DNS Thresholds
DNS_SPOOF_THRESHOLD = 3 #multiple IPs in a single DNS response


def packet_callback(packet):
    # Append each captured packet to the list
    captured_packets.append(packet)
    #print("**NEW PACKET** " + packet.show())  # Examine problematic packets

    #ensuring UDP raw data handling
    if packet.haslayer(UDP):  # Step 1
        udp_payload = packet[UDP].payload  # Step 2
        #if udp_payload:  # Step 3
            #print(f"UDP Payload: {bytes(udp_payload)}")  # Step 4

    # Detect DNS spoofing

    if packet.haslayer(DNS) and packet[DNS].qr == 1: #DNS response
        domain = packet[DNS].qd.qname.decode() if packet[DNS].qd else "Unknown"
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
            if(len(dns_tracker[domain])) > DNS_SPOOF_THRESHOLD:
                 print(f"\n[ALERT] Potential DNS spoofing detected for {domain}")


def sniff_packets():
    #Captures sniff packets indefinitely
    sniff(prn=packet_callback, store=False)

def main():
    output_file = r'C:\Cyber\projects\captured_packets.pcap'
    print("Starting packet sniffer. Packets will be saved to " + output_file)

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