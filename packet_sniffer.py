from scapy.all import sniff, wrpcap

#Define a list to store captured packets
captured_packets = []


def packet_callback(packet):
    # Append each captured packet to the list
    captured_packets.append(packet)
    print(packet.summary())

def main():
    output_file = r'C:\Cyber\projects\captured_packets.pcap'
    print("Starting packet sniffer. Packets will be saved to '{output_file}'")
    # Capture packets indefinitely
    sniff(prn=packet_callback, store=False, count = 1000)
    #On stopping , write the captured packets to a file
    print(f"\nSaving {len(captured_packets)} packets to '{output_file}'...")
    wrpcap(output_file,captured_packets)
    print("Packets saved successfully")


if __name__ == "__main__":
    main()
