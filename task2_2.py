import pyshark
from collections import defaultdict


def read_pcap_file(pcap_file):
    ip_counter = defaultdict(lambda: defaultdict(int))

    cap = pyshark.FileCapture(pcap_file, display_filter='ip || ipv6')
    for packet in cap:
        if hasattr(packet, 'ip'):
            if packet.ip.src is not None:
                ip_counter[packet.ip.src]['From'] += 1
            if packet.ip.dst is not None:
                ip_counter[packet.ip.dst]['To'] += 1
        elif hasattr(packet, 'ipv6'):
            if packet.ipv6.src is not None:
                ip_counter[packet.ipv6.src]['From'] += 1
            if packet.ipv6.dst is not None:
                ip_counter[packet.ipv6.dst]['To'] += 1

    cap.close()
    return ip_counter


def write_statistics_to_file(statistics, output_file):
    with open(output_file, 'w') as f:
        f.write("IPv4 Statistics:\n")
        for ip, directions in statistics.items():
            if ':' not in ip:
                f.write(f'IP: {ip}\n')
                for direction, count in directions.items():
                    f.write(f'  {direction}: {count}\n')
                f.write('\n')

        f.write("\nIPv6 Statistics:\n")
        for ip, directions in statistics.items():
            if ':' in ip:
                f.write(f'IP: {ip}\n')
                for direction, count in directions.items():
                    f.write(f'  {direction}: {count}\n')
                f.write('\n')


pcap_file_path = 'home_network_traffic.pcap'
statistics_file_path = 'ip_statistics.txt'

ip_statistics = read_pcap_file(pcap_file_path)
write_statistics_to_file(ip_statistics, statistics_file_path)

