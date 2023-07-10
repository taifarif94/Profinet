import pandas as pd
from collections import defaultdict
import struct
import socket


def calculate_IP_checksum(header):
    # concatenate adjacent bytes in header to form words, skip checksum bytes
    words = [header[i] + header[i + 1][2:] for i in range(0, len(header), 2) if i not in [10, 11]]

    # convert hexadecimal words to decimal and calculate sum
    total = sum(int(word, 16) for word in words)

    # calculate carries
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)

    # one's complement
    checksum = total ^ 0xffff
    checksumList =[]
    checksumList.extend([('0x' + (hex(checksum)[2:].zfill(4))[:2]),('0x' + (hex(checksum)[2:].zfill(4))[2:])])

    return checksumList

    # return '0x' + format(checksum, '04x')  # return checksum as hexadecimal

def calculate_checksum_UDP(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s



def Print_C_String():
    # Dynamic Array
    profinet_data = []

    # Ethernet II
    # Destination:
    profinet_data.extend(['0xa0','0x36','0x9f','0x31','0xa7','0x2e'])
    # Source:
    profinet_data.extend(['0x00','0xa0','0x45','0xd5','0x37','0xca'])
    # Type
    profinet_data.extend(['0x08','0x00'])

    # Internet Protocol
    # Version
    # Header Length
    profinet_data.append('0x45')
    # Differentiated Services Field
    profinet_data.append('0x00')
    # Total Length
    profinet_data.extend(['0x00','0xa0'])
    # Identification
    profinet_data.extend(['0x52', '0xee'])
    # Flags
    profinet_data.append('0x40')
    # Fragment Offset
    profinet_data.append('0x00')
    # Time to Live
    profinet_data.append('0x40')
    # Protocol: UDP
    profinet_data.append('0x11')
    # Header Checksum
    profinet_data.extend(['0x00','0x00'])
    # Source Address
    profinet_data.extend(['0xc0','0xa8','0x00','0x32'])
    # Destination Address
    profinet_data.extend(['0xc0', '0xa8', '0x00', '0x19'])

    # User Datagram Protocol
    # Source Port
    profinet_data.extend(['0xe3', '0xdc'])
    # Destination Port
    profinet_data.extend(['0xc0', '0x46'])
    # Length
    profinet_data.extend(['0x00', '0x8c'])
    # Checksum
    profinet_data.extend(['0x00', '0x00'])

    # Distributed Computing Environment / Remote Procedure Call
    # Version
    profinet_data.append('0x04')
    # Packet Type: Response
    profinet_data.append('0x02')
    # Flags 1
    profinet_data.append('0x20')
    # Flags 2
    profinet_data.append('0x00')
    # Data Representation (Order: Big-endian, Char: ASCII, Float: IEEE)
    profinet_data.extend(['0x00','0x00','0x00'])
    # Serial High
    profinet_data.append('0x00')
    # Object UUID: dea00000-6c97-11d1-8271-000100010174
    profinet_data.extend(['0xde', '0xa0', '0x00', '0x00', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71', '0x00', '0x01', '0x00', '0x01', '0x01', '0x74'])
    # Interface: PNIO(Device Interface) UUID: dea00001 -6c97-11d1 - 8271 - 00a02442df7d
    profinet_data.extend(['0xde', '0xa0', '0x00', '0x01', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71', '0x00', '0xa0', '0x24', '0x42', '0xdf', '0x7d'])
    # Activity: 2408f1bc-506f-4bf7-b414-be82fb0fa038
    profinet_data.extend(['0x24', '0x08', '0xf1', '0xbc', '0x50', '0x6f', '0x4b', '0xf7', '0xb4', '0x14', '0xbe', '0x82', '0xfb', '0x0f', '0xa0', '0x38'])
    # Server Boot time
    profinet_data.extend(['0x5d','0x61','0x73','0x2d'])
    # Interface Ver: 1
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])
    # Sequence Number: 43
    profinet_data.extend(['0x00', '0x00', '0x00', '0x2b'])
    # Opnum: 4
    profinet_data.extend(['0x00', '0x04'])
    # Interface Hint: 0xffff
    profinet_data.extend(['0xff', '0xff'])
    # Activity Hint: 0xffff
    profinet_data.extend(['0xff', '0xff'])
    # Fragment len: 52
    profinet_data.extend(['0x00', '0x34'])
    # Fragment num: 0
    profinet_data.extend(['0x00', '0x00'])
    # Auth proto: None (0)
    profinet_data.append('0x00')
    # Serial Low: 0x00
    profinet_data.append('0x00')

    # Profinet IO (Device), Control
    # Status: OK
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])
    # ArgsLength: 32 (0x00000020)
    profinet_data.extend(['0x00', '0x00', '0x00', '0x20'])
    # Array: Max: 66412, Offset: 0, Size: 32
    # MaximumCount: 66412
    profinet_data.extend(['0x00', '0x01', '0x03', '0x6c'])
    # Offset: 0 (0x00000000)
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])
    # ActualCount: 32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x20'])

    # IODControlReq Prm End.req: Session:10, Command: ParameterEnd, Properties:0x0
    # BlockHeader: Type=IODControlReq Prm End.req, Length=28(+4), Version=1.0
    # BlockType: IODControlRes Prm End.res (0x8110)
    profinet_data.extend(['0x81', '0x10'])
    # BlockLength: 28 (0x001c)
    profinet_data.extend(['0x00', '0x1c'])
    # BlockVersionHigh: 1
    profinet_data.append('0x01')
    # BlockVersionLow: 0
    profinet_data.append('0x00')
    # Reserved: 0x0000
    profinet_data.extend(['0x00', '0x00'])
    # ARUUID: daef5a22-0fce-4145-bd75-998938d106c1
    profinet_data.extend(['0xda', '0xef', '0x5a', '0x22', '0x0f', '0xce', '0x41', '0x45', '0xbd', '0x75', '0x99', '0x89', '0x38', '0xd1', '0x06', '0xc1'])
    # SessionKey: 10
    profinet_data.extend(['0x00', '0x0a'])
    # Reserved: 0x0000
    profinet_data.extend(['0x00', '0x00'])
    # ControlCommand: 0x0008, Done
    profinet_data.extend(['0x00', '0x08'])
    # ControlBlockProperties: Reserved (0x0000)
    profinet_data.extend(['0x00', '0x00'])

    # Questions: Should both BlockVersionHigh and BlockVersionLow should be added to
    #     the block header? Moreover, What version should they have?

    # RealIdentificationData with BlockVersionLow =1
    # BlockHeader, NumberOfAPIs, (API, NumberOfSlots, (SlotNumber, ModuleIdentNumber,
    # NumberOfSubslots, (SubslotNumber, SubmoduleIdentNumber)*)*)*

    # BlockHeader
    # BlockType, BlockLength, BlockVersionHigh, BlockVersionLow
    # BlockType:0x0013
    # profinet_data.append('0x0013')
    profinet_data.extend(['0x00', '0x13'])
    # BlockLength-> based on the following, it's fixed at 22 bytes or 0x0016
    # profinet_data.append('0x0016')
    profinet_data.extend(['0x00', '0x16'])
    # BlockVersionHigh
    # Version 1
    profinet_data.append('0x01')
    # BlockVersionLow
    # Version 1
    profinet_data.append('0x01')

    # NumberOfAPIs
    # Coded as data type Unsigned16.
    # profinet_data.append('0x0001')
    profinet_data.extend(['0x00', '0x01'])
    # API
    # Coded as data type Unsigned32
    # profinet_data.append('0x0000FFFF')
    profinet_data.extend(['0x00', '0x00', '0xFF', '0xFF'])
    # NumberOfSlots
    # Coded as data type Unsigned16.
    # profinet_data.append('0x0001')
    profinet_data.extend(['0x00', '0x01'])
    # SlotNumber
    # Coded as data type Unsigned16
    # profinet_data.append('0x0000')
    profinet_data.extend(['0x00', '0x00'])

    # ModuleIdentNumber
    # Coded as data type Unsigned32
    # profinet_data.append('0x00000001')
    profinet_data.extend(['0x00', '0x00','0x00','0x01'])

    # NumberOfSubslots
    # Coded as data type Unsigned16.
    # profinet_data.append('0x0001')
    profinet_data.extend(['0x00', '0x01'])

    # SubSlotNumber
    # Coded as data type Unsigned16.
    # profinet_data.append('0x0001')
    profinet_data.extend(['0x00', '0x01'])

    # SubmoduleIdentNumber
    # Coded as data type Unsigned32.
    # profinet_data.append('0x00000001')
    profinet_data.extend(['0x00', '0x00','0x00', '0x01'])




    # The length field in the IP layer needs to be set.
    # Assuming the number of Octets in the Ethernet layer remain the same for each packet,
    # The length of the IP packet is then length of the profinet_data list minus 14.
    # because Ethernet II layer is 14 bytes long.
    # The subscript that refers to the IP length is also then: 16 and 17.

    ip_length = len(profinet_data)-14
    # IP length is converted to hex, '0x' is ignored, and zfill adds zeros to the left to make the
    # total length to 4 (2 bytes) if it is already not so.
    profinet_data[16] = '0x'+(hex(ip_length)[2:].zfill(4))[:2]
    profinet_data[17] = '0x'+(hex(ip_length)[2:].zfill(4))[2:]

    # Since the function returns a list, relevant checksum bits are re-assigned the correct values.
    profinet_data[24] = calculate_IP_checksum(profinet_data[14:34])[0]
    profinet_data[25] = calculate_IP_checksum(profinet_data[14:34])[1]

    # Assuming the IP header length is always 20 bytes, the UDP length is then:
    # IP length minus 20.
    UDP_length = ip_length -20
    profinet_data[38] = '0x' + (hex(UDP_length)[2:].zfill(4))[:2]
    profinet_data[39] = '0x' + (hex(UDP_length)[2:].zfill(4))[2:]

    # Since the UDP header is always 8 bytes, the UDP payload minus the header, meaning
    # the DCE/ RPC length would be Length - 8.
    DCE_RPC_Length = UDP_length - 8

    # Since the Header lengths of the layers are fixed as follows:
    # Ethernet II = 14 bytes
    # IP = 20 bytes
    # UDP = 8 bytes
    # The remaining DCE_RPC_Data can be calculated as:
    DCE_RPC = profinet_data.copy()[((14+20+8)):]
    # Getting the source and destination IP addresses:
    # Convert list elements to integers, then to strings, then join them with periods
    source_address_ip = ".".join(str(int(x, 16)) for x in profinet_data.copy()[26:30])
    dest_address_ip = ".".join(str(int(x, 16)) for x in profinet_data.copy()[30:34])
    source_address_ip = socket.inet_aton(source_address_ip)
    dest_address_ip = socket.inet_aton(dest_address_ip)
    placeholder = 0
    protocol = socket.IPPROTO_UDP
    # construct the pseudo header
    psh = struct.pack('!4s4sBBH', source_address_ip, dest_address_ip, placeholder, protocol, UDP_length)
    # get the UDP header (minus the checksum)
    udp_header_without_checksum = profinet_data.copy()[34:40]
    udp_header_without_checksum = "".join(x[2:] for x in udp_header_without_checksum)
    udp_header_without_checksum = bytes.fromhex(udp_header_without_checksum)

    DCE_RPC_hex = "".join(x[2:] for x in DCE_RPC)
    DCE_RPC_hex = bytes.fromhex(DCE_RPC_hex)
    print(DCE_RPC_hex)

    # pad the data if necessary
    if len(DCE_RPC_hex) % 2 != 0:
        DCE_RPC_hex += b'\0'
    # concatenate the pseudo-header, the udp header without checksum, zeros for checksum and the data
    packet = psh + udp_header_without_checksum + b'\x00\x00' + DCE_RPC_hex
    # compute the checksum
    calculated_checksum = calculate_checksum_UDP(packet)
    calculated_checksum = socket.htons(calculated_checksum)  # convert to network byte order
    # insert the calculated checksum into profinet_data
    profinet_data[40] = '0x' + format(calculated_checksum, '04x')[0:2]
    profinet_data[41] = '0x' + format(calculated_checksum, '04x')[2:]

    dce_fragment_length = (len(profinet_data)-(14+20+8+80))

    profinet_data[116] = '0x' + format(dce_fragment_length, '04x')[0:2]
    profinet_data[117] = '0x' + format(dce_fragment_length, '04x')[2:]

    print(f"{calculated_checksum:04x}")

    with open('RealidentificationDataLow_alarm_1325.txt', 'w') as f:
        for i in range(0, len(profinet_data), 8):
            f.write(', '.join(profinet_data[i:i + 8]) + '\n')








# Parse the pcap file and get the dataframes
Print_C_String()


#

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
# IP Version and Headerlength refer to the same hexadecimal value
# Flag and Fragment offset overlap for the first byte








#
#
#