from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import csv
import time

flows = {}


def create_bidirectional_key(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol
):

    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:
        return (endpoint1, endpoint2, protocol)

    return (endpoint2, endpoint1, protocol)


def process_packet(packet):

    current_time = time.time()

    # -----------------------------
    # IPv4 / IPv6 handling
    # -----------------------------

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = 4

    elif IPv6 in packet:

        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = 6

    else:
        return

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0

    # -----------------------------
    # TCP processing
    # -----------------------------

    if TCP in packet:

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        flags = packet[TCP].flags

        if flags.S:
            syn_count = 1

        if flags.A:
            ack_count = 1

        if flags.F:
            fin_count = 1

        if flags.R:
            rst_count = 1

    # -----------------------------
    # UDP processing
    # -----------------------------

    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    flow_key = create_bidirectional_key(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )

    packet_size = len(packet)

    if flow_key not in flows:

        flows[flow_key] = {

            # Preserve original direction
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,

            "start_time": current_time,
            "end_time": current_time,

            "packet_count": 1,
            "total_bytes": packet_size,

            "syn_count": syn_count,
            "ack_count": ack_count,
            "fin_count": fin_count,
            "rst_count": rst_count,

            "ip_version": ip_version
        }

    else:

        flow = flows[flow_key]

        flow["end_time"] = current_time
        flow["packet_count"] += 1
        flow["total_bytes"] += packet_size

        flow["syn_count"] += syn_count
        flow["ack_count"] += ack_count
        flow["fin_count"] += fin_count
        flow["rst_count"] += rst_count


print("Collecting traffic for 300 seconds...\n")

start_capture = time.time()

sniff(
    prn=process_packet,
    store=False,
    timeout=300
)

capture_duration = time.time() - start_capture

print(f"\nCapture completed in {capture_duration:.2f} seconds")
print(f"Total flows: {len(flows)}")

csv_file = "data.csv"

with open(csv_file, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "ip_version",
        "protocol",
        "duration",
        "packet_count",
        "total_bytes",
        "avg_packet_size",
        "packets_per_sec",
        "syn_count",
        "ack_count",
        "fin_count",
        "rst_count"
    ])

    for flow_key, flow in flows.items():

        duration = (
            flow["end_time"]
            - flow["start_time"]
        )

        if duration <= 0:
            duration = 0.001

        avg_packet_size = (
            flow["total_bytes"]
            / flow["packet_count"]
        )

        packets_per_sec = (
            flow["packet_count"]
            / duration
        )

        writer.writerow([
            flow["src_ip"],
            flow["src_port"],
            flow["dst_ip"],
            flow["dst_port"],
            flow["ip_version"],
            flow_key[2],
            round(duration, 3),
            flow["packet_count"],
            flow["total_bytes"],
            round(avg_packet_size, 2),
            round(packets_per_sec, 2),
            flow["syn_count"],
            flow["ack_count"],
            flow["fin_count"],
            flow["rst_count"]
        ])

print(f"\nSaved flow data to {csv_file}")

print("\nSample flows:\n")

for i, (flow_key, flow) in enumerate(flows.items()):

    if i >= 10:
        break

    print(flow_key)
    print(flow)
    print()
