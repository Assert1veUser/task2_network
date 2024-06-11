import pyshark
import requests
import json


def get_geolocation(ip_address):
    response = requests.get(f"http://ip-api.com/json/{ip_address}")
    data = json.loads(response.text)
    return data



def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='ip')
    ip_addresses = set()

    # Извлечение всех IP-адресов из пакетов
    for packet in cap:
        if hasattr(packet, 'ip'):
            ip_addresses.add(packet.ip.src)
            ip_addresses.add(packet.ip.dst)

    # Получение географических данных для каждого IP-адреса
    geolocation_data = {}
    for ip in ip_addresses:
        geolocation_data[ip] = get_geolocation(ip)

    return geolocation_data



def save_statistics(statistics, output_file):
    with open(output_file, 'w') as file:
        for ip, data in statistics.items():
            file.write(f"IP: {ip}\n")
            file.write(f"Country: {data.get('country')}\n")
            file.write(f"Region: {data.get('regionName')}\n")
            file.write(f"City: {data.get('city')}\n")
            file.write(f"ISP: {data.get('isp')}\n")
            file.write(f"Latitude: {data.get('lat')}\n")
            file.write(f"Longitude: {data.get('lon')}\n")
            file.write("\n")




pcap_file = 'home_network_traffic.pcap'  # Замените на путь к вашему файлу pcap
output_file = 'ip_info.txt'

statistics = process_pcap(pcap_file)
save_statistics(statistics, output_file)