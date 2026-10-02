from scapy.all import IP, TCP, UDP, sniff


def packet_callback(packet):
  if IP in packet:
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto

    proto_name = "OTHER"
    if proto == 6:
      proto_name = "TCP"
    elif proto == 17:
      proto_name = "UDP"
    elif proto == 1:
      proto_name = "ICMP"

    print(
        f"[+] Packet Captured: Protocol: {proto_name} | Source: {src_ip} -->"
        f" Destination: {dst_ip}"
    )

    if packet.haslayer(TCP) or packet.haslayer(UDP):
      payload = bytes(packet.payload)
      if payload:
        print(
            f"    Payload Preview (First 50 bytes):"
            f" {payload[:50]!r}\n--------------------------------------------------"
        )


def main():
  print("Starting Network Sniffer... Press Ctrl+C to stop.")
  sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
  main()