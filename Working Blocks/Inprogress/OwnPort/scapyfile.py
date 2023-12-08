from scapy.all import *
import re

def read_hex_file(file_path):
    try:
        with open(file_path, 'r') as file:
            hex_data = file.read()
            # Remove all non-hexadecimal characters except for '0x' prefixes
            hex_data = re.sub(r'[^0-9a-fA-Fx,]', '', hex_data)
            # Split the string into individual hex bytes
            hex_bytes = hex_data.split(',')
            # Remove empty strings and '0x' prefixes, and ensure each byte has 2 hex digits
            hex_bytes = [byte.strip()[2:] if byte.strip().startswith('0x') else byte.strip() for byte in hex_bytes if byte.strip()]
            hex_bytes = [byte if len(byte) == 2 else '0' + byte for byte in hex_bytes if len(byte) <= 2]
            # Join the bytes back into a single string
            clean_hex_data = ''.join(hex_bytes)
            return bytes.fromhex(clean_hex_data)
    except ValueError as e:
        error_pos = str(e).split('position ')[1]
        print(f"Error near position {error_pos}:")
        print(hex_data[max(0, int(error_pos)-10):int(error_pos)+10])
        return None
    except Exception as e:
        print(f"Error reading or processing file: {e}")
        return None

def create_pcap_from_hex(hex_data, output_file):
    try:
        packet = Ether(hex_data)
        wrpcap(output_file, packet)
        print(f"PCAP file created: {output_file}")
    except Exception as e:
        print(f"Error creating pcap file: {e}")

def main():
    input_file = 'PDPortDataRealExtended.txt'  # Update this path
    output_file = 'output.pcap'

    hex_data = read_hex_file(input_file)
    if hex_data:
        create_pcap_from_hex(hex_data, output_file)

if __name__ == '__main__':
    main()
