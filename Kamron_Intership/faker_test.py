import random
import time
import csv
from datetime import datetime, timedelta

# Define the IP address pool
ip_pool = [f"192.168.1.{i}" for i in range(1, 255)] + \
          [f"10.0.0.{i}" for i in range(1, 255)] + \
          [f"172.16.0.{i}" for i in range(1, 255)]

# Define the port pool with higher frequency for ports 80 and 443
port_pool = [80, 443] * 10 + list(range(1024, 65536))

# Generate a realistic timestamp
def generate_timestamp(start_time):
    return start_time + timedelta(seconds=random.randint(1, 60))

# Generate a single network packet
def generate_packet(src_ip, dst_ip, src_port, dst_port, timestamp):
    return {
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': random.choice(['TCP', 'UDP']),
        'size': random.randint(40, 1500)
    }

# Generate a flow of packets between two IP addresses
def generate_flow(start_time, src_ip, dst_ip):
    flow = []
    num_packets = random.randint(5, 20)
    src_port = random.choice(port_pool)
    dst_port = random.choice(port_pool)
    timestamp = start_time

    for _ in range(num_packets):
        packet = generate_packet(src_ip, dst_ip, src_port, dst_port, timestamp)
        flow.append(packet)
        timestamp = generate_timestamp(timestamp)

    return flow

# Generate network traffic data
def generate_network_data(num_packets):
    data = []
    start_time = datetime.now() - timedelta(days=1)

    while len(data) < num_packets:
        src_ip = random.choice(ip_pool)
        dst_ip = random.choice(ip_pool)
        
        # Ensure src_ip and dst_ip are not the same
        while dst_ip == src_ip:
            dst_ip = random.choice(ip_pool)
        
        flow = generate_flow(start_time, src_ip, dst_ip)
        data.extend(flow)
        start_time = generate_timestamp(start_time)

    return data[:num_packets]

# Save network data to a CSV file
def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'size']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for packet in data:
            writer.writerow(packet)

# Generate and save the data
num_packets = 10000  # Adjust as needed
network_data = generate_network_data(num_packets)
save_to_csv(network_data, 'advanced_network_traffic.csv')