import socket
import binascii
import requests
import folium

from api import api_key

packet_buffer = {}
protos = {"0806": "ARP", "0800": "IPV4", "86DD": "IPV6", "17": "UDP", "1": "ICMP", "58": "ICMPV6", "6": "TCP",
          "2": "IGMP"}
map_coordinates = {}

checked_ips = ["0.0.0.0", "255.255.255.255", "127.0.0.1"]


def append_coord_file(coord):
    f = open("coordinations.txt", "a")
    f.write(str(coord["latitude"]) + " ")
    f.write(str(coord["longitude"]) + "\n")
    f.close()


def read_coord_file():
    f = open('coordinations.txt', 'r')
    word = f.readline()
    index = 0
    while word != '':
        map_coordinates.update({index: (word.split(" ")[0], word.split(" ")[1][:len(word.split(" ")[1]) - 1])})
        index += 1
        word = f.readline()
    print(map_coordinates)


def geo_location(ip_addr, api):
    url = f"http://api.ipstack.com/{ip_addr}?access_key={api}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()


def init_map(coordinates):
    map_center = coordinates[0]
    global_map = folium.Map(location=map_center, zoom_start=10)

    for coord in coordinates.values():
        folium.Marker(location=coord, popup=str(coord)).add_to(global_map)
    return global_map


def create_map(coordinates):
    global_map = init_map(coordinates)
    global_map.save('global_map2.html')


def print_interface():
    print(""" /$$$$$$$                     /$$                   /$$            /$$$$$$            /$$  /$$$$$$   /$$$$$$                   
| $$__  $$                   | $$                  | $$           /$$__  $$          |__/ /$$__  $$ /$$__  $$                  
| $$  \ $$ /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$  /$$$$$$        | $$  \__/ /$$$$$$$  /$$| $$  \__/| $$  \__//$$$$$$   /$$$$$$ 
| $$$$$$$/|____  $$ /$$_____/| $$  /$$/ /$$__  $$|_  $$_/        |  $$$$$$ | $$__  $$| $$| $$$$    | $$$$   /$$__  $$ /$$__  $$
| $$____/  /$$$$$$$| $$      | $$$$$$/ | $$$$$$$$  | $$           \____  $$| $$  \ $$| $$| $$_/    | $$_/  | $$$$$$$$| $$  \__/
| $$      /$$__  $$| $$      | $$_  $$ | $$_____/  | $$ /$$       /$$  \ $$| $$  | $$| $$| $$      | $$    | $$_____/| $$      
| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/      |  $$$$$$/| $$  | $$| $$| $$      | $$    |  $$$$$$$| $$      
|__/      \_______/ \_______/|__/  \__/ \_______/   \___/         \______/ |__/  |__/|__/|__/      |__/     \_______/|__/ """)


def get_eth_type(raw_data):
    return binascii.hexlify(raw_data[12:14]).decode('utf-8')


def extract_eth_header(raw_data):
    dest_mac_addr = binascii.hexlify(raw_data[0:6]).decode('utf-8')
    src_mac_addr = binascii.hexlify(raw_data[6:12]).decode('utf-8')
    eth_type = get_eth_type(raw_data)
    return ':'.join(dest_mac_addr[i:i + 2] for i in range(0, 12, 2)).upper(), ':'.join(
        src_mac_addr[i:i + 2] for i in range(0, 12, 2)).upper(), eth_type.upper()


def extract_ipv4_header(raw_data):
    return "Protocol: " + protos[str(raw_data[23])] + " SRC IP: " + ipv4(raw_data[26:30]) + " DST IP: " + ipv4(
        raw_data[30:34]) + "\n"  # IP header src ip starts
    # at byte 26 (the 27 byte)


def ipv4(raw_bytes):
    return '.'.join(str(byte) for byte in raw_bytes[0:4])


def ipv6(raw_bytes):
    return ':'.join(binascii.hexlify(raw_bytes[i:i + 2]).decode('utf-8') for i in range(0, 16, 2))


def extract_arp_header(raw_data):
    return "WHO IS " + ipv4(raw_data[38:42]) + " TELL " + ipv4(raw_data[28:32]) + "\n"


def extract_ipv6_header(raw_data):
    return "Protocol: " + protos[str(raw_data[20])] + " SRC IP: " + ipv6(raw_data[22:38]) + " DST ADDR: " + ipv6(
        raw_data[38:54]) + "\n"


def percentages():
    ipv4 = 0
    ipv6 = 0
    arp = 0
    size = len(packet_buffer.keys())
    for k in packet_buffer:
        if packet_buffer[k][1] == "0800":
            ipv4 += 1
        elif packet_buffer[k][1] == "86DD":
            ipv6 += 1
        else:
            arp += 1
    print("IPV4: " + str((ipv4 / size) * 100) + "%", "IPV6: " + str((ipv6 / size) * 100) + "%",
          "ARP: " + str((arp / size) * 100) + "%")


def get_data(sock_id):
    eth_header = packet_buffer[sock_id]
    if eth_header == "8000":
        return packet_buffer[sock_id][34:]
    if eth_header == "86DD":
        return packet_buffer[sock_id][54:]
    else:
        return -1


def countries():
    pass


def stats():
    percentages()
    countries()


def sniff():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # 0X0003 is equivalent to ETHER_P_ALL,
    # and means listen on all ports.
    sock_id = 1
    amount = int(input("How many packets would you like to sniff (Write -1 if you're interested in infinite mode) "))
    while amount != 0 or amount < 0:
        packet = s.recvfrom(65535)[0]
        packet_buffer.update({sock_id: [packet, get_eth_type(packet).upper()]})
        eth_header = extract_eth_header(packet)
        if not protos.keys().__contains__(eth_header[2]):
            print(eth_header)
            break
        print("ID: " + str(sock_id) + " SRC MAC: " + eth_header[1] + " -------> " + "DST MAC: " + eth_header[
            0] + " Protocol: " + protos[eth_header[2]])
        if eth_header[2] == "0800":
            print(extract_ipv4_header(packet))
        if eth_header[2] == "0806":
            print(extract_arp_header(packet))
        if eth_header[2] == "86DD":
            print(extract_ipv6_header(packet))
        amount -= 1
        sock_id += 1
    print("Captured " + str(sock_id - 1) + " packets!")

    is_stats = input("Would you like statistics? y/n")
    if is_stats == "y":
        stats()

    show_map = input("Display map of first 10 packets? y/n")
    if show_map == "y":
        for i in range(0, len(packet_buffer.keys())):

            if protos[packet_buffer[i+1][1]] == "IPV4" and ipv4(packet_buffer[i+1][0][30:34]) not in checked_ips:
                append_coord_file(geo_location(ipv4(packet_buffer[i+1][0][30:34]), api_key))
                checked_ips.append(ipv4(packet_buffer[i+1][0][30:34]))
            if protos[packet_buffer[i+1][1]] == "IPV6" and ipv6(packet_buffer[i+1][0][38:54]) not in checked_ips:
                append_coord_file(geo_location(ipv6(packet_buffer[i+1][0][38:54]), api_key))
                checked_ips.append(ipv6(packet_buffer[i+1][0][38:54]))

        read_coord_file()
        init_map(map_coordinates)
        create_map(map_coordinates)



