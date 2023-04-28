from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

packets = [
    Ether() / IP(len=100) / UDP() / Raw(b'A' * 80),
    Ether() / IP(len=110) / UDP() / Raw(b'A' * 90),
    Ether() / IP(len=120) / UDP() / Raw(b'A' * 100),
    Ether() / IP(len=130) / UDP() / Raw(b'A' * 110),
    Ether() / IP(len=140) / UDP() / Raw(b'A' * 120)
]

packets_TCP = [
    Ether() / IP() / TCP(sport=12345, dport=80, flags='S', window=8192) / Raw(b'B' * 130),
    Ether() / IP() / TCP(sport=12346, dport=80, flags='S', window=16384) / Raw(b'B' * 140),
    Ether() / IP() / TCP(sport=12347, dport=443, flags='S', window=32768) / Raw(b'B' * 150),
    Ether() / IP() / TCP(sport=12348, dport=443, flags='A', window=65535) / Raw(b'B' * 160),
    Ether() / IP() / TCP(sport=12349, dport=22, flags='PA', window=65535) / Raw(b'B' * 170),
]

wrpcap('test_small_UDP.pcap', packets)
wrpcap('test_small_TCP.pcap', packets_TCP)