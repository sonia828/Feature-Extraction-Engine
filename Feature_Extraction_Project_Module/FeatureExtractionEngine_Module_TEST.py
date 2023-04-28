import unittest
import os
import numpy as np
import pandas as pd
import scapy.all as scapy
from collections import Counter
from FeatureExtractionEngine_Module import process_pcap

class TestProcessPcap(unittest.TestCase):

    def test_process_pcap_output_type(self):
        # Test if the output is a Pandas DataFrame
        filename = './test_data/test.pcap'
        num_packets = 10
        label = 'Test'
        result = process_pcap(filename, num_packets, label)
        self.assertIsInstance(result, pd.DataFrame)

    def test_process_pcap_output_columns(self):
        # Test if the output DataFrame has the expected columns
        filename = './test_data/test.pcap'
        num_packets = 10
        label = 'Test'
        expected_columns = [
            'IP_len_avg', 'IP_len_max', 'IP_len_min', 'IP_len_std', 'IP_len_var', 'IP_len_sum', 'destination_len_avg', 'destination_len_max',
            'destination_len_min', 'destination_len_std', 'destination_len_var', 'destination_len_sum','payload_len_avg',
            'payload_len_max', 'payload_len_min', 'payload_len_std', 'payload_len_var', 'payload_len_sum', 'UDP_len_avg','UDP_len_max',
            'UDP_len_min', 'UDP_len_std', 'UDP_len_var', 'UDP_len_sum', 'udp_checksum_avg', 'udp_checksum_max', 'udp_checksum_min',
            'udp_checksum_std', 'udp_checksum_var', 'udp_checksum_dist', 'dst_mac_mode', 'src_mac_mode', 'eth_type_mode', 'ip_version_mode',
            'ip_ihl_mode', 'ip_tos_mode', 'ip_flags_mode', 'ip_ttl_mode', 'ip_proto_mode', 'src_ip_mode', 'udp_sport_mode', 'udp_dport_mode',
            'TCP_sport_most_common', 'TCP_sport_std', 'TCP_sport_min', 'TCP_sport_max', 'TCP_sport_range', 'TCP_dport_most_common', 'TCP_dport_std', 'TCP_dport_min',
            'TCP_dport_max', 'TCP_dport_range', 'TCP_flags_most_common', 'TCP_flags_std', 'TCP_flags_min', 'TCP_flags_max', 'TCP_flags_range', 'TCP_window_avg',
            'TCP_window_max', 'TCP_window_min', 'TCP_window_std', 'TCP_window_var', 'TCP_window_sum',
            'avg_packet_rate', 'Label'
        ]
        result = process_pcap(filename, num_packets, label)
        self.assertListEqual(list(result.columns), expected_columns)

    def test_process_pcap_output_length(self):
        # Test if the output DataFrame has the expected number of rows (samples)
        filename = './test_data/test.pcap'
        num_packets = 10
        label = 'Test'
        result = process_pcap(filename, num_packets, label)
        packets = scapy.rdpcap(filename)
        packet_count = len(packets)
        expected_rows = packet_count // num_packets
        if packet_count % num_packets != 0:
            expected_rows += 1

        self.assertEqual(len(result), expected_rows)

    def test_process_pcap_output_values_UDP(self):
        # Test if the output DataFrame has the correct sample values
        filename = './test_data/test_small_UDP.pcap'
        num_packets = 5
        label = 'Test'
        result = process_pcap(filename, num_packets, label)

        expected_values = {
            'IP_len_avg': 120.0,
            'IP_len_max': 140,
            'IP_len_min': 100,
            'IP_len_std': 14.14213562373095,
            'IP_len_var': 200.0,
            'IP_len_sum': 600,
            'payload_len_avg': 80.0,
            'payload_len_max': 100,
            'payload_len_min': 60,
            'payload_len_std': 14.14213562373095,
            'payload_len_var': 200.0,
            'payload_len_sum': 400,
            'destination_len_avg': 9.0,
            'destination_len_max': 9,
            'destination_len_min': 9,
            'destination_len_std': 0.0,
            'destination_len_var': 0.0,
            'destination_len_sum': 45,
            'UDP_len_avg': 114.0,
            'UDP_len_max': 134,
            'UDP_len_min': 94,
            'UDP_len_std': 14.14213562373095,
            'UDP_len_var': 200.0,
            'UDP_len_sum': 570,
            'udp_checksum_avg': 43097.0,
            'udp_checksum_max': 64408,
            'udp_checksum_min': 16883,
            'udp_checksum_std': 16221.543514721403,
            'udp_checksum_var': 0263138474.0,
            'udp_checksum_dist': Counter({52903: 1, 34893: 1, 16883: 1, 64408: 1, 46398: 1}),
            'dst_mac_mode': 'ff:ff:ff:ff:ff:ff',
            'src_mac_mode': '00:00:00:00:00:00',
            'eth_type_mode': 2048,
            'ip_version_mode': 4,
            'ip_ihl_mode': 5,
            'ip_tos_mode': 0,
            'ip_flags_mode': 0,
            'ip_ttl_mode': 64,
            'ip_proto_mode': 17,
            'src_ip_mode': '127.0.0.1',
            'udp_sport_mode': 53,
            'udp_dport_mode': 53,
            'TCP_sport_most_common': None,
            'TCP_sport_std': None,
            'TCP_sport_min': None,
            'TCP_sport_max': None,
            'TCP_sport_range': None,
            'TCP_dport_most_common': None,
            'TCP_dport_std': None,
            'TCP_dport_min': None,
            'TCP_dport_max': None,
            'TCP_dport_range': None,
            'TCP_flags_most_common': None,
            'TCP_flags_std': None,
            'TCP_flags_min': None,
            'TCP_flags_max': None,
            'TCP_flags_range': None,
            'TCP_window_avg': None,
            'TCP_window_max': None,
            'TCP_window_min': None,
            'TCP_window_std': None,
            'TCP_window_var': None,
            'TCP_window_sum': None,
            'avg_packet_rate': 4194.6308724832215,
            'Label': 'Test'
        }

        result_dict = result.iloc[0].to_dict()

        for key in expected_values:
            if key not in result_dict:
                self.fail(f"Key '{key}' not found in result_dict")
            elif isinstance(expected_values[key], Counter):
                self.assertEqual(result_dict[key], expected_values[key])
            else:
                self.assertAlmostEqual(result_dict[key], expected_values[key], delta=1e-8)

    def test_process_pcap_output_values_TCP(self):
            # Test if the output DataFrame has the correct sample values
            filename = './test_data/test_small_TCP.pcap'
            num_packets = 5
            label = 'Test'
            result = process_pcap(filename, num_packets, label)

            expected_values = {
                'IP_len_avg': 190.0,
                'IP_len_max': 210,
                'IP_len_min': 170,
                'IP_len_std': 14.14213562373095,
                'IP_len_var': 200.0,
                'IP_len_sum': 950,
                'payload_len_avg': 150.0,
                'payload_len_max': 170,
                'payload_len_min': 130,
                'payload_len_std': 14.14213562373095,
                'payload_len_var': 200.0,
                'payload_len_sum': 750,
                'destination_len_avg': 9.0,
                'destination_len_max': 9,
                'destination_len_min': 9,
                'destination_len_std': 0.0,
                'destination_len_var': 0.0,
                'destination_len_sum': 45,
                'UDP_len_avg': 0,
                'UDP_len_max': 0,
                'UDP_len_min': 0,
                'UDP_len_std': 0,
                'UDP_len_var': 0,
                'UDP_len_sum': 0,
                'udp_checksum_avg': 0,
                'udp_checksum_max': 0,
                'udp_checksum_min': 0,
                'udp_checksum_std': 0,
                'udp_checksum_var': 0,
                'udp_checksum_dist': 0,
                'dst_mac_mode': 'ff:ff:ff:ff:ff:ff',
                'src_mac_mode': '00:00:00:00:00:00',
                'eth_type_mode': 2048,
                'ip_version_mode': 4,
                'ip_ihl_mode': 5,
                'ip_tos_mode': 0,
                'ip_flags_mode': 0,
                'ip_ttl_mode': 64,
                'ip_proto_mode': 6,
                'src_ip_mode': '127.0.0.1',
                'udp_sport_mode': None,
                'udp_dport_mode': None,
                'TCP_sport_most_common': 12345,
                'TCP_sport_std': 1.4142135623730951,
                'TCP_sport_min': 12345,
                'TCP_sport_max': 12349,
                'TCP_sport_range': 4,
                'TCP_dport_most_common': 80,
                'TCP_dport_std': 188.49785144664116,
                'TCP_dport_min': 22,
                'TCP_dport_max': 443,
                'TCP_dport_range': 421,
                'TCP_flags_most_common': 2,
                'TCP_flags_std': 9.173875952943773,
                'TCP_flags_min': 2,
                'TCP_flags_max': 24,
                'TCP_flags_range': 22,
                'TCP_window_avg': 37682.8,
                'TCP_window_max': 65535,
                'TCP_window_min': 8192,
                'TCP_window_std': 24079.001286598246,
                'TCP_window_var': 579798302.9599999,
                'TCP_window_sum': 188414,
                'avg_packet_rate': 4468.275245755139,
                'Label': 'Test'
            }

            result_dict = result.iloc[0].to_dict()

            for key in expected_values:
                if key not in result_dict:
                    self.fail(f"Key '{key}' not found in result_dict")
                elif isinstance(expected_values[key], Counter):
                    self.assertEqual(result_dict[key], expected_values[key])
                else:
                    self.assertAlmostEqual(result_dict[key], expected_values[key], delta=1e-8)

if __name__ == '__main__':
    unittest.main()