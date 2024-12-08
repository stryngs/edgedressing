#!/usr/bin/python3

from scapy.all import sniff, TCP, IP, Raw, wrpcap
from collections import defaultdict
from queue import Queue
from threading import Thread
import argparse
import atexit

# Dictionary to store ongoing TCP sessions
tcp_streams = defaultdict(lambda: {"data": b"", "next_seq": None, "buffer": {}, "processed": False})

# Queue to hold captured packets for processing
packet_queue = Queue()

# List to store captured packets for PCAP saving if --pcap is enabled
captured_packets = []

def process_packet_from_queue():
    """
    Worker function to process packets from the queue.
    """
    while True:
        packet = packet_queue.get()
        if packet is None:  # Sentinel to signal thread termination
            break
        process_packet(packet)
        packet_queue.task_done()

def process_packet(packet):
    """
    Process each packet to reconstruct TCP streams and optionally save for PCAP.
    """
    # Add the packet to captured packets if --pcap is enabled
    if args.pcap:
        captured_packets.append(packet)

    if IP in packet and TCP in packet and Raw in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload = tcp_layer.payload.load if Raw in packet else b""

        # Identify the TCP stream
        stream_id = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
        seq = tcp_layer.seq
        payload_length = len(payload)

        if tcp_streams[stream_id]["next_seq"] is None:
            tcp_streams[stream_id]["next_seq"] = seq + payload_length
            tcp_streams[stream_id]["data"] += payload
        else:
            if seq == tcp_streams[stream_id]["next_seq"]:
                tcp_streams[stream_id]["data"] += payload
                tcp_streams[stream_id]["next_seq"] += payload_length
                process_buffered_packets(stream_id)
            else:
                tcp_streams[stream_id]["buffer"][seq] = payload

        # Process HTTP data if headers are complete and not already processed
        if b"\r\n\r\n" in tcp_streams[stream_id]["data"] and not tcp_streams[stream_id]["processed"]:
            http_data = tcp_streams[stream_id]["data"].decode(errors="ignore")

            # Mark the stream as processed to avoid duplicates
            tcp_streams[stream_id]["processed"] = True

            # Check for "Cookie:" in requests
            if "Cookie:" in http_data:
                cookies = extract_request_cookies(http_data)
                if cookies:
                    print(f"\n--- Cookies Found in Request Stream ---")
                    for cookie in cookies:
                        print(f"- {cookie}")
                    print(f"Stream ID: {stream_id}")
                    print(f"Cookie Count: {len(cookies)}")
                    print("--- End of Request Cookies ---\n")

            # Check for "Set-Cookie:" in responses
            if "Set-Cookie:" in http_data:
                cookies = extract_response_cookies(http_data)
                if cookies:
                    print(f"\n--- Cookies Found in Response Stream ---")
                    for cookie in cookies:
                        print(f"- {cookie}")
                    print(f"Stream ID: {stream_id}")
                    print(f"Cookie Count: {len(cookies)}")
                    print("--- End of Response Cookies ---\n")

def process_buffered_packets(stream_id):
    """
    Process out-of-order packets stored in the buffer.
    """
    stream = tcp_streams[stream_id]
    while stream["next_seq"] in stream["buffer"]:
        payload = stream["buffer"].pop(stream["next_seq"])
        payload_length = len(payload)
        stream["data"] += payload
        stream["next_seq"] += payload_length

def extract_request_cookies(payload):
    """
    Extract cookies from the 'Cookie:' header in an HTTP payload (requests).
    """
    cookies = []
    lines = payload.split("\r\n")
    for line in lines:
        if line.startswith("Cookie:"):
            # Split cookies by "; " for cleaner output
            cookies.extend(line[len("Cookie: "):].strip().split("; "))
    return cookies

def extract_response_cookies(payload):
    """
    Extract cookies from the 'Set-Cookie:' header in an HTTP payload (responses).
    """
    cookies = []
    lines = payload.split("\r\n")
    for line in lines:
        if line.startswith("Set-Cookie:"):
            cookies.append(line[len("Set-Cookie: "):].strip())
    return cookies

def save_pcap(pcap_file):
    """
    Save captured packets to a PCAP file.
    """
    if captured_packets:
        print(f"Saving {len(captured_packets)} packets to {pcap_file}...")
        wrpcap(pcap_file, captured_packets)
        print(f"Captured packets saved to {pcap_file}.")
    else:
        print("No packets captured to save.")

def start_sniffer(interface="lo", pcap_file=None, num_threads=1):
    """
    Start sniffing packets on the specified interface and process them with threads.
    """
    print(f"Starting sniffer on interface {interface} with {num_threads} thread(s). Press Ctrl+C to stop.")

    # Start worker threads
    threads = []
    for _ in range(num_threads):
        thread = Thread(target=process_packet_from_queue)
        thread.daemon = True
        threads.append(thread)
        thread.start()

    try:
        sniff(
            iface=interface,
            prn=packet_queue.put,
            filter="tcp",
            store=0
        )
    finally:
        # Send a sentinel to stop worker threads
        for _ in threads:
            packet_queue.put(None)
        for thread in threads:
            thread.join()

        # Save packets when the sniffer stops
        if pcap_file:
            save_pcap(pcap_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cookie Sniffer with Optional PCAP Storage and Threading")
    parser.add_argument("--interface", type=str, default="lo", help="Interface to sniff on (default: lo)")
    parser.add_argument("--pcap", type=str, help="Enable PCAP storage and specify output file name (e.g., foo for foo.pcap)")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for processing packets (default: 1)")
    args = parser.parse_args()

    pcap_file = f"{args.pcap}.pcap" if args.pcap else None

    # Ensure packets are saved on exit
    if pcap_file:
        atexit.register(save_pcap, pcap_file)

    start_sniffer(interface=args.interface, pcap_file=pcap_file, num_threads=args.threads)
