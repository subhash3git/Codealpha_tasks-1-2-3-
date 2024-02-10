import scapy.all as scapy

def sniff_packets(interface):
    print("[+] Sniffing started on interface " + interface)
    scapy.sniff(iface=interface, prn=process_packet, store=False)

def process_packet(packet):

    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"[+] {src_ip} --> {dst_ip} Protocol: {protocol}")


        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"    [TCP] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"    [UDP] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")


        print(packet.summary())


sniff_packets('Wi-Fi')
