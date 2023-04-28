import sys
import FeatureExtractionEngine_Module

if len(sys.argv) != 4:
    print("Usage: python FeatureExtractionEngine_Module_run.py <input_folder_or_file> <num_packets> <label>")
    sys.exit(1)

input_path = sys.argv[1]
num_packets = int(sys.argv[2])
label = sys.argv[3]

FeatureExtractionEngine_Module.process_pcap_files(input_path, num_packets, label)

