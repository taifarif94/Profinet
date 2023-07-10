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

    # LogBookData with
    # BlockVersionLow = 0
    # BlockHeader, ActualLocalTimeStamp, NumberOfLogEntries, (LocalTimeStamp, ARUUID,
    # PNIOStatus, EntryDetail)*

    # BlockHeader BlockType, BlockLength, BlockVersionHigh, BlockVersionLow
    # BlockType: 0x0019
    profinet_data.extend(['0x00', '0x19'])
    # BlockLength
    # 5.2.1.2 Coding of the field BlockLength
    # This field shall be coded as data type Unsigned16 with the values according to Table 557.
    # Table 557 – BlockLength
    # Value
    # (hexadecimal) Meaning
    # 0x0000 – 0x0002 Reserved
    # 0x0003 – 0xFFFF Number of octets without counting the fields BlockType and BlockLength
    # ???

    # 5.2.1.3 Coding of the field BlockVersionHigh
    # 8796 This field shall be coded as data type Unsigned8 with the values according to Table 558.
    # 8797 Table 558 – BlockVersionHigh
    # Value
    # (hexadecimal) Meaning Use
    # 0x00 Reserved —
    # 0x01 Version 1 Indicates version 1
    # 0x02 – 0xFF Reserved —
    profinet_data.append('0x01')

    # 5.2.1.4 Coding of the field BlockVersionLow
    # 8800 This field shall be coded as data type Unsigned8 with the values according to Table 559.
    # 8801 Table 559 – BlockVersionLow
    # Value
    # (hexadecimal) Meaning Use
    # 0x00 Version 0 Indicates version 0
    # 0x01 Version 1 Indicates version 1
    # 0x02 – 0xFF Version 2 to version 255 Indicates version 2 to 255
    profinet_data.append('0x00')

    # 5.2.24.1 Coding of the field ActualLocalTimeStamp
    # 11937 This field shall be coded as data type Unsigned64 according to Table 1047.
    # 11938 Table 1047 – ActualLocalTimeStamp
    # Value
    # (hexadecimal)
    # Meaning Use
    # 0x0000000000000000 – 0xFFFFFFFFFFFFFFFF Contains the current cycle count
    # value when reading the logbook. —
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00'])

    # 5.2.24.3 Coding of the field NumberOfLogEntries
    # 11945 This field shall be coded as data type Unsigned16 according to Table 1049.
    # 11946 Table 1049 – NumberOfLogEntries
    # Value Meaning Use
    # 0 Reserved —
    # Other Number of log entries —
    profinet_data.extend(['0x00', '0x01'])

    # 5.2.24.2 Coding of the field LocalTimeStamp
    # 11941 This field shall be coded as data type Unsigned64 according to Table 1048.
    # 11942 Table 1048 – LocalTimeStamp
    # Value
    # (hexadecimal)
    # Meaning Use
    # 0x0000000000000000 – 0xFFFFFFFFFFFFFFFF
    # Contains the current cycle count
    # when storing the entry to the
    # logbook.
    # —
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x01'])

    # 0000000000000000000000000000000000000000000000000000000000000000
    # 5.2.4.47 Coding of the field ARUUID
    # 9306 This field shall be coded as data type UUID according to Table 635, Table 636, Table 637, and
    # 9307 Table 638.
    # 9308 Table 635 – ARUUID
    # Value
    # (UUID)
    # Meaning Use
    # 00000000-0000-0000-0000-000000000000 Reserved The value NIL indicates the usage of the
    # implicit AR.
    # 6+8+2 Octets
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00','0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x01'])

    # 5.2.6 Coding section related to PNIOStatus
    # 9617 5.2.6.1 General
    # 9618 In general, the values ErrorCode=0, ErrorDecode=0, ErrorCode1=0 and ErrorCode2=0 shall be
    # 9619 used to indicate “okay”.
    # 9620 Furthermore, in case of an illegal combination of address parameters within an IODReadReq
    # 9621 the values ErrorCode=“IODReadRes”, ErrorDecode=“PNIORW”, ErrorCode1=“access-invalid
    # 9622 area” and ErrorCode2 may be used to indicate the faulty parameter.
    # 9623 NOTE An illegal address combination is for example TargetARUUID == NIL and ARUUID == NIL in
    # 9624 ReadExpectedIdentification service.
    # Table 691 – Values of ErrorCode for negative responses
    # Value
    # (hexadecimal)
    # Meaning Use
    # 0x00 Reserved
    # Special case “No Error”:
    # ErrorCode = 0,
    # ErrorDecode = 0,
    # ErrorCode1 = 0,
    # ErrorCode2 = 0
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])

    # 5.2.24.4 Coding of the 11948 field EntryDetail
    # 11949 This field shall be coded as data type Unsigned32 according to protocol machine behavior and
    # 11950 Table 1050.
    # 11951 Table 1050 – EntryDetail
    # Value
    # (hexadecimal)
    # Meaning Use
    # 0x00000000 No detail —
    # Other Value derived from the signaling protocol
    # machine —
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])










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

    with open('alarm_1325.txt', 'w') as f:
        for i in range(0, len(profinet_data), 8):
            f.write(', '.join(profinet_data[i:i + 8]) + '\n')


# Questions: Should both BlockVersionHigh and BlockVersionLow should be added to
#     the block header? Moreover, What version should they have?

    # RealIdentificationData with BlockVersionLow
    # BlockHeader, NumberOfAPIs, (API, NumberOfSlots, (SlotNumber, ModuleIdentNumber,
    # NumberOfSubslots, (SubslotNumber, SubmoduleIdentNumber)*)*)*

    # BlockHeader
    # BlockType, BlockLength, BlockVersionHigh, BlockVersionLow
    # BlockType:0x0013
    profinet_data.append('0x0013')
    # BlockLength-> based on the following, it's fixed at 22 bytes or 0x0016
    profinet_data.append('0x0016')
    # BlockVersionHigh
    # Version 1
    profinet_data.append('0x01')
    # BlockVersionLow
    # Version 1
    profinet_data.append('0x01')

    # NumberOfAPIs
    # Coded as data type Unsigned16.
    profinet_data.append('0x0001')

    # API
    # Coded as data type Unsigned32
    profinet_data.append('0x0000FFFF')

    # NumberOfSlots
    # Coded as data type Unsigned16.
    profinet_data.append('0x0001')

    # SlotNumber
    # Coded as data type Unsigned16
    profinet_data.append('0x0000')

    # ModuleIdentNumber
    # Coded as data type Unsigned32
    profinet_data.append('0x00000001')

    # NumberOfSubslots
    # Coded as data type Unsigned16.
    profinet_data.append('0x0001')

    # SubSlotNumber
    # Coded as data type Unsigned16.
    profinet_data.append('0x0001')

    # SubmoduleIdentNumber
    # Coded as data type Unsigned32.
    profinet_data.append('0x00000001')





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