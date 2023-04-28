import os
import sys
import time
import datetime
import socket
import pathlib
import numpy as np
import pandas as pd
import scapy.all as scapy
from collections import Counter

def process_pcap(filename, num_packets, label):
    packets = scapy.rdpcap(filename)

    def getSample():
        i: int = 0
        current_sample: list = []

        for p in packets:
            packet = p/scapy.Ether()
            current_sample.append(packet)
            i+=1

            if i % num_packets == 0:
                yield current_sample
                current_sample = []

        # Yield any remaining packets in the last sample
        if current_sample:
            yield current_sample

    dataset_raw = []

    for sample in getSample():
        sample_values = {}
        temp = {}

        temp['IP_len'] = []
        temp['destination_len'] = []
        temp['payload_len'] = []
        temp['UDP_len'] = []
        temp['udp_checksum'] = []

        # Additional features
        temp['dst_mac'] = []  # Destination MAC addresses
        temp['src_mac'] = []  # Source MAC addresses
        temp['eth_type'] = []  # Ethernet types
        temp['ip_version'] = []  # IP versions
        temp['ip_ihl'] = []  # IP header lengths
        temp['ip_tos'] = []  # IP Type of Service values
        temp['ip_flags'] = []  # IP fragmentation flags
        temp['ip_ttl'] = []  # IP Time to Live values
        temp['ip_proto'] = []  # IP protocols (e.g., UDP, TCP, ICMP, etc.)
        temp['src_ip'] = []  # Source IP addresses
        temp['udp_sport'] = []  # UDP source ports
        temp['udp_dport'] = []  # UDP destination ports
        #TCP
        temp['TCP_sport'] = [] #soure port
        temp['TCP_dport'] = [] #destination port
        temp['TCP_flags'] = [] #tcp flags
        temp['TCP_window'] = [] #window size

        first_pkt_time = sample[0].time  # Get the timestamp of the first packet
        last_pkt_time = sample[-1].time  # Get the timestamp of the last packet
        duration = last_pkt_time - first_pkt_time  # Compute the duration of the capture in second

        for p in sample:
            
            temp['IP_len'].append(p.len)
    
            # Extracting Ethernet layer information
            if p.haslayer('Ethernet'):
                temp['dst_mac'].append(p['Ethernet'].dst)
                temp['src_mac'].append(p['Ethernet'].src)
                temp['eth_type'].append(p['Ethernet'].type)
            
            # Extracting IP layer information
            if p.haslayer('IP'):
                temp['ip_version'].append(p['IP'].version)
                temp['ip_ihl'].append(p['IP'].ihl)
                temp['ip_tos'].append(p['IP'].tos)
                temp['ip_flags'].append(p['IP'].flags)
                temp['ip_ttl'].append(p['IP'].ttl)
                temp['ip_proto'].append(p['IP'].proto)
                temp['src_ip'].append(p['IP'].src)
                
                destination_len = len(p['IP'].dst)
                temp['destination_len'].append(destination_len)

            # Extracting Raw layer information   
            if p.haslayer('Raw'):
                temp['payload_len'].append(len(p['Raw'].load))
            
            # Extracting UDP layer information
            if p.haslayer('UDP'):
                udp_pkt = p['UDP']
                udp_len = len(udp_pkt.payload)
                temp['UDP_len'].append(udp_len)
                
                udp_checksum = p['UDP'].chksum
                temp['udp_checksum'].append(udp_checksum)
                
                temp['udp_sport'].append(p['UDP'].sport)# UDP source port
                temp['udp_dport'].append(p['UDP'].dport)  # UDP destination port

            # Extracting TCP layer information
            if p.haslayer('TCP'):
                temp['TCP_sport'].append(p['TCP'].sport)
                temp['TCP_dport'].append(p['TCP'].dport)
                temp['TCP_flags'].append(int(p['TCP'].flags))
                temp['TCP_window'].append(p['TCP'].window)

        #length of the ip packet
        sample_values['IP_len_avg'] = sum(temp['IP_len'])/len(temp['IP_len'])
        sample_values['IP_len_max'] = max(temp['IP_len'])
        sample_values['IP_len_min'] = min(temp['IP_len'])
        sample_values['IP_len_std'] = np.std(temp['IP_len'])
        sample_values['IP_len_var'] = np.var(temp['IP_len'])
        sample_values['IP_len_sum'] = sum(temp['IP_len'])

        #length of the destination IP address in bytes
        sample_values['destination_len_avg'] = sum(temp['destination_len']) / len(temp['destination_len'])
        sample_values['destination_len_max'] = max(temp['destination_len'])
        sample_values['destination_len_min'] = min(temp['destination_len'])
        sample_values['destination_len_std'] = np.std(temp['destination_len'])
        sample_values['destination_len_var'] = np.var(temp['destination_len'])
        sample_values['destination_len_sum'] = sum(temp['destination_len'])

        #length of the payload (or data) of each packet.
        sample_values['payload_len_avg'] = sum(temp['payload_len'])/len(temp['payload_len'])
        sample_values['payload_len_max'] = max(temp['payload_len'])
        sample_values['payload_len_min'] = min(temp['payload_len'])
        sample_values['payload_len_std'] = np.std(temp['payload_len'])
        sample_values['payload_len_var'] = np.var(temp['payload_len'])
        sample_values['payload_len_sum'] = sum(temp['payload_len'])

        #length of the UDP (User Datagram Protocol) payload in each packet
        if len(temp['UDP_len']) > 0:
            sample_values['UDP_len_avg'] = sum(temp['UDP_len']) / len(temp['UDP_len'])
            sample_values['UDP_len_max'] = max(temp['UDP_len'])
            sample_values['UDP_len_min'] = min(temp['UDP_len'])
            sample_values['UDP_len_std'] = np.std(temp['UDP_len'])
            sample_values['UDP_len_var'] = np.var(temp['UDP_len'])
            sample_values['UDP_len_sum'] = sum(temp['UDP_len'])
        else:
            sample_values['UDP_len_avg'] = 0
            sample_values['UDP_len_avg'] = 0
            sample_values['UDP_len_max'] = 0
            sample_values['UDP_len_min'] = 0
            sample_values['UDP_len_std'] = 0
            sample_values['UDP_len_var'] = 0
            sample_values['UDP_len_sum'] = 0

        if len(temp['udp_checksum']) > 0:
            sample_values['udp_checksum_avg'] = sum(temp['udp_checksum'])/len(temp['udp_checksum'])
            sample_values['udp_checksum_max'] = max(temp['udp_checksum'])
            sample_values['udp_checksum_min'] = min(temp['udp_checksum'])
            sample_values['udp_checksum_std'] = np.std(temp['udp_checksum'])
            sample_values['udp_checksum_var'] = np.var(temp['udp_checksum'])
            sample_values['udp_checksum_dist'] = Counter(temp['udp_checksum'])
        else:
            sample_values['udp_checksum_avg'] = 0
            sample_values['udp_checksum_max'] = 0
            sample_values['udp_checksum_min'] = 0
            sample_values['udp_checksum_std'] = 0
            sample_values['udp_checksum_var'] = 0
            sample_values['udp_checksum_dist'] = 0

        # Calculate the most common value (mode) for new features
        sample_values['dst_mac_mode'] = Counter(temp['dst_mac']).most_common(1)[0][0]
        sample_values['src_mac_mode'] = Counter(temp['src_mac']).most_common(1)[0][0]
        sample_values['eth_type_mode'] = Counter(temp['eth_type']).most_common(1)[0][0]
        sample_values['ip_version_mode'] = Counter(temp['ip_version']).most_common(1)[0][0]
        sample_values['ip_ihl_mode'] = Counter(temp['ip_ihl']).most_common(1)[0][0]
        sample_values['ip_tos_mode'] = Counter(temp['ip_tos']).most_common(1)[0][0]
        sample_values['ip_flags_mode'] = Counter(temp['ip_flags']).most_common(1)[0][0]
        sample_values['ip_ttl_mode'] = Counter(temp['ip_ttl']).most_common(1)[0][0]
        sample_values['ip_proto_mode'] = Counter(temp['ip_proto']).most_common(1)[0][0]
        sample_values['src_ip_mode'] = Counter(temp['src_ip']).most_common(1)[0][0]

        if temp['udp_sport']:
            sample_values['udp_sport_mode'] = Counter(temp['udp_sport']).most_common(1)[0][0]
        else:
            sample_values['udp_sport_mode'] = None
        if temp['udp_dport']:
            sample_values['udp_dport_mode'] = Counter(temp['udp_dport']).most_common(1)[0][0]
        else:
             sample_values['udp_dport_mode'] = None

        # Additional TCP features
        #sample_values['TCP_sport_most_common'] = get_most_common(temp['TCP_sport'])
        if temp['TCP_sport']:
            sample_values['TCP_sport_most_common'] = Counter(temp['TCP_sport']).most_common(1)[0][0]
            sample_values['TCP_sport_std'] = np.std(temp['TCP_sport'])
            sample_values['TCP_sport_min'] = min(temp['TCP_sport'])
            sample_values['TCP_sport_max'] = max(temp['TCP_sport'])
            sample_values['TCP_sport_range'] = max(temp['TCP_sport']) - min(temp['TCP_sport'])
        else:
            sample_values['TCP_sport_most_common'] = None
            sample_values['TCP_sport_std'] = None
            sample_values['TCP_sport_min'] = None
            sample_values['TCP_sport_max'] = None
            sample_values['TCP_sport_range'] = None

        if temp['TCP_dport']:
            sample_values['TCP_dport_most_common'] = Counter(temp['TCP_dport']).most_common(1)[0][0]
            sample_values['TCP_dport_std'] = np.std(temp['TCP_dport'])
            sample_values['TCP_dport_min'] = min(temp['TCP_dport'])
            sample_values['TCP_dport_max'] = max(temp['TCP_dport'])
            sample_values['TCP_dport_range'] = max(temp['TCP_dport']) - min(temp['TCP_dport'])
        else:
            sample_values['TCP_dport_most_common'] = None
            sample_values['TCP_dport_std'] = None
            sample_values['TCP_dport_min'] = None
            sample_values['TCP_dport_max'] = None
            sample_values['TCP_dport_range'] = None

        if temp['TCP_flags']:
            sample_values['TCP_flags_most_common'] = Counter(temp['TCP_flags']).most_common(1)[0][0]
            sample_values['TCP_flags_std'] = np.std(temp['TCP_flags'])
            sample_values['TCP_flags_min'] = min(temp['TCP_flags'])
            sample_values['TCP_flags_max'] = max(temp['TCP_flags'])
            sample_values['TCP_flags_range'] = max(temp['TCP_flags']) - min(temp['TCP_flags'])
        else:
            sample_values['TCP_flags_most_common'] = None
            sample_values['TCP_flags_std'] = None
            sample_values['TCP_flags_min'] = None
            sample_values['TCP_flags_max'] = None
            sample_values['TCP_flags_range'] = None

        if temp['TCP_window']:
            sample_values['TCP_window_avg'] = sum(temp['TCP_window'])/len(temp['TCP_window'])
            sample_values['TCP_window_max'] = max(temp['TCP_window'])
            sample_values['TCP_window_min'] = min(temp['TCP_window'])
            sample_values['TCP_window_std'] = np.std(temp['TCP_window'])
            sample_values['TCP_window_var'] = np.var(temp['TCP_window'])
            sample_values['TCP_window_sum'] = sum(temp['TCP_window'])
        else:
            sample_values['TCP_window_avg'] = None
            sample_values['TCP_window_max'] = None
            sample_values['TCP_window_min'] = None
            sample_values['TCP_window_std'] = None
            sample_values['TCP_window_var'] = None
            sample_values['TCP_window_sum'] = None

        if duration == 0:
            sample_values['avg_packet_rate'] = 'No Packet Rate'
        else:
            sample_values['avg_packet_rate'] = float(len(sample) / duration) 

        sample_values['Label'] = label

        dataset_raw.append(sample_values)

    dataset = pd.DataFrame(dataset_raw)

    return dataset

def process_pcap_files(input_path, num_packets, label):
    if os.path.isdir(input_path):
        input_folder = input_path
        output_folder = input_folder + '_csv_output'
        input_is_folder = True
    elif os.path.isfile(input_path):
        input_file = input_path
        if os.path.dirname(input_file) == "":
            output_folder = input_file + '_csv_output'
        else: output_folder = os.path.dirname(input_file) + '_csv_output'
        input_is_folder = False
    else:
        print("Error: Input path is not a folder or a file")
        sys.exit(1)

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    if input_is_folder:
        for file in os.listdir(input_folder):
            if file.endswith('.pcap'):
                pcap_path = os.path.join(input_folder, file)
                df = process_pcap(pcap_path, num_packets, label)
                output_file = os.path.splitext(file)[0] + '.csv'
                output_path = os.path.join(output_folder, output_file)
                df.to_csv(output_path, index=False)
    else:
        if input_file.endswith('.pcap'):
            df = process_pcap(input_file, num_packets, label)
            output_file = os.path.splitext(os.path.basename(input_file))[0] + '.csv'
            output_path = os.path.join(output_folder, output_file)
            df.to_csv(output_path, index=False)
            