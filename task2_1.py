import pyshark
from collections import Counter


def read_pcap_file(pcap_file):
    protocol_counter = Counter()

    cap = pyshark.FileCapture(pcap_file, display_filter='ip || ipv6')
    for packet in cap:
        if 'ICMP' in packet:
            protocol_counter['ICMP'] += 1
        elif 'ICMPV6' in packet:
            protocol_counter['ICMPv6'] += 1
        elif 'TCP' in packet:
            protocol_counter['TCP'] += 1
        elif 'UDP' in packet:
            protocol_counter['UDP'] += 1
        elif 'IP' in packet:
            protocol_counter['IGMP'] += 1
        elif 'IPV6' in packet:
            protocol_counter['IPv6'] += 1
        else:
            protocol_counter['Non-IP'] += 1

    cap.close()
    return protocol_counter


def write_statistics_to_file(statistics, output_file):
    with open(output_file, 'w') as f:
        for protocol, count in statistics.items():
            f.write(f'{protocol}: {count}\n')


pcap_file_path = 'home_network_traffic.pcap'
statistics_file_path = 'statistics_protocol.txt'

protocol_statistics = read_pcap_file(pcap_file_path)
write_statistics_to_file(protocol_statistics, statistics_file_path)

