import pandas as pd
from collections import defaultdict
import struct
import socket

# def indexNumber(currentElement, list):
# IP header indexes fixed at 14:33
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
    # Start Counting Length
    IPLenStart=len(profinet_data.copy());
    profinet_data.append('0x45')
    # Differentiated Services Field
    profinet_data.append('0x00')
    # Total Length
    profinet_data.extend(['0x00','0x00'])
    # Identification
    profinet_data.extend(['0x17', '0x5b'])
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
    profinet_data.extend(['0xeb', '0xb0'])
    # Destination Port
    profinet_data.extend(['0xc0', '0x15'])
    # Length
    profinet_data.extend(['0x00', '0x00'])
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
    # Activity: fa601515-3229-46f3-b6e0-a6380a583807
    profinet_data.extend(['0xfa', '0x60', '0x15', '0x15', '0x32', '0x29', '0x46', '0xf3', '0xb6', '0xe0', '0xa6', '0x38', '0x0a', '0x58', '0x38', '0x07'])
    # Server Boot time
    profinet_data.extend(['0x5d','0x61','0x78','0x39'])
    # Interface Ver: 1
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])
    # Sequence Number: 6
    profinet_data.extend(['0x00', '0x00', '0x00', '0x06'])
    # Opnum: 2
    profinet_data.extend(['0x00', '0x02'])
    # Interface Hint: 0xffff
    profinet_data.extend(['0xff', '0xff'])
    # Activity Hint: 0xffff
    profinet_data.extend(['0xff', '0xff'])
    # Fragment len: 124
    profinet_data.extend(['0x00', '0x00'])
    dceRpcFragLenIndex = len(profinet_data)-2
    # Fragment num: 0
    profinet_data.extend(['0x00', '0x00'])
    # Auth proto: None (0)
    profinet_data.append('0x00')
    # Serial Low: 0x00
    profinet_data.append('0x00')

    # Stub data/ Fragment length marker.
    # In order to calculate the correct fragment length, a marker is being placed here. This means it will be deducted from the total profinet data to calculate the length.
    fragment_length_start_marker = len(profinet_data.copy())


    # Profinet IO (Device), Read
    # Status: OK
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])
    # ArgsLength: 104 (0x00000068)
    profinet_data.extend(['0x00', '0x00', '0x00', '0x68'])
    # Args Length Index
    profinetIoArgsLengthIndex = len(profinet_data)-4
    # Array: Max: 66412, Offset: 0, Size: 104
    # MaximumCount: 66412
    profinet_data.extend(['0x00', '0x01', '0x03', '0x6c'])
    # Offset: 0 (0x00000000)
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])
    # ActualCount: 104
    profinet_data.extend(['0x00', '0x00', '0x00', '0x68'])
    # Actual Count Index
    profinetIoActualCountIndex = len(profinet_data)-4

    # Args Length and ActualCount is assumed to be everything else contained in the Profinet IO (Device)
    profinetIoArgsLengthStart = len(profinet_data)
    # IODReadResHeader: Seq:4, Api:0x0, Slot:0x0/0x8000, Len:40, AddVal1:0, AddVal2:0
    # BlockHeader: Type=IODReadResHeader, Length=60(+4), Version=1.0
    # BlockType: IODReadResHeader (0x8009)
    profinet_data.extend(['0x80', '0x09'])
    # BlockLength: 60 (0x003c)
    profinet_data.extend(['0x00', '0x3c'])

    # IODReadResHeader BlockLength Index
    IODReadResHeaderBlockLengthIndex = len(profinet_data)-2

    # IODReadResHeader BlockLength Marker Start
    IODReadResHeaderBlockLengthStart = len(profinet_data)






    # BlockVersionHigh: 1
    profinet_data.append('0x01')
    # BlockVersionLow: 0
    profinet_data.append('0x00')
    # SeqNumber: 4
    profinet_data.extend(['0x00', '0x04'])
    # ARUUID: e3f022b4-5acc-41a1-be98-40e300b9c071
    profinet_data.extend(['0xe3', '0xf0', '0x22', '0xb4', '0x5a', '0xcc', '0x41', '0xa1', '0xbe', '0x98', '0x40', '0xe3', '0x00', '0xb9', '0xc0', '0x71'])
    # API: 0x00000000
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])
    # SlotNumber: 0x0000
    profinet_data.extend(['0x00', '0x00'])
    # SubslotNumber: 0x8000
    profinet_data.extend(['0x80', '0x00'])

    # padding
    # Question: Usually the padding is at the end of the block but here the
    # block doesn't continue and padding is in the middle. Why is that?
    # Answer: It is fixed at 2 in the manual.
    profinet_data.extend(['0x00', '0x00'])
    # Index: RealIdentificationData for one slot (0xc001)
    profinet_data.extend(['0xc0', '0x01'])
    # RecordDataLength: 40 (0x00000028)
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00'])

    IODReadResHeaderRecordDataLengthIndex = len(profinet_data)-4

    # AdditionalValue1: 0
    profinet_data.extend(['0x00', '0x00'])
    # AdditionalValue2: 0
    profinet_data.extend(['0x00', '0x00'])
    # Another Padding here.
    # This is fixed at 20 as per the manual
    profinet_data.extend(['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00','0x00', '0x00', '0x00', '0x00', '0x00','0x00', '0x00', '0x00', '0x00', '0x00'])
    IODReadResHeaderBlockLengthEnd = len(profinet_data)

    IODReadResHeaderBlockLength = IODReadResHeaderBlockLengthEnd - IODReadResHeaderBlockLengthStart
    profinet_data[IODReadResHeaderBlockLengthIndex] = '0x' + format(IODReadResHeaderBlockLength, '04x')[0:2]
    profinet_data[IODReadResHeaderBlockLengthIndex+1] = '0x' + format(IODReadResHeaderBlockLength, '04x')[2:]



    # fragment_length_end_marker = len(profinet_data.copy())




    # We assume for the time being that this block is included in the stub data.
    # PDIRGlobalData with
    # BlockVersionLow = 2
    # BlockHeader, Padding, Padding, IRDataUUID, MaxBridgeDelay, NumberOfPorts,
    # (MaxPortTxDelay, MaxPortRxDelay, MaxLineRxDelay, YellowTime)*

    # Start of Whole block length
    BlockLengthStart = len(profinet_data)

    # BlockHeader BlockType, BlockLength, BlockVersionHigh, BlockVersionLow
    # BlockType: 0x0206
    profinet_data.extend(['0x02', '0x06'])
    # BlockLength
    # 0x0003 – 0xFFFF Number of octets without counting the fields BlockType and BlockLength
    profinet_data.extend(['0x00', '0x00'])

    # BlockLengthIndex
    BlockLengthIndex = len(profinet_data) - 2

    # BlockVersionHigh
    profinet_data.append('0x01')

    # BlockVersionLow
    profinet_data.append('0x02')

    # Padding
    profinet_data.append('0x00')

    # Padding
    profinet_data.append('0x00')

    # IRDataUUID
    profinet_data.extend(['0xe3', '0xf0', '0x22', '0xb4', '0x5a', '0xcc', '0x41', '0xa1', '0xbe', '0x98', '0x40', '0xe3', '0x00', '0xb9', '0xc0', '0x71'])

    # MaxBridgeDelay
    # Unsigned32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])

    # NumberOfPorts
    # Unsigned32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])

    # MaxPortTxDelay
    # Unsigned32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])

    # MaxPortRxDelay
    # Unsigned32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])

    # MaxLineRxDelay
    # Unsigned32
    profinet_data.extend(['0x00', '0x00', '0x00', '0x01'])

    # YellowTime
    # 0x1AE0
    profinet_data.extend(['0x1A', '0xE0'])



    # Block Length End
    BlockLengthEnd = len(profinet_data)


    # Ensure Unsigned32 alignment
    block_length_current = BlockLengthEnd - BlockLengthStart
    print(block_length_current)
    padding_needed = (block_length_current % 4)
    print("Padding needed: ")
    print(padding_needed)
    # Insert padding octets right after the BlockHeader
    for _ in range(padding_needed):
        profinet_data.append('0x00')

    # Stub data/ Fragment length End marker.
    fragment_length_end_marker = len(profinet_data.copy())
    # Block Length End
    BlockLengthEnd = len(profinet_data)

    # Total Length end
    totalLengthEnd = len(profinet_data.copy())
    print("Number of elements in profinet_data: ", len(profinet_data))

    # End



    # The length field in the IP layer needs to be set.
    # Assuming the number of Octets in the Ethernet layer remain the same for each packet,
    # The length of the IP packet is then length of the profinet_data list minus 14.
    # because Ethernet II layer is 14 bytes long.
    # The subscript that refers to the IP length is also then: 16 and 17.

    ip_length = totalLengthEnd-IPLenStart
    # IP length is converted to hex, '0x' is ignored, and zfill adds zeros to the left to make the
    # total length to 4 (2 bytes) if it is already not so.
    profinet_data[16] = '0x'+(hex(ip_length)[2:].zfill(4))[:2]
    profinet_data[17] = '0x'+(hex(ip_length)[2:].zfill(4))[2:]


    # Assigning the correct Arg length in Profinet IO Device (Read)
    profinetIoArgsLength = totalLengthEnd-profinetIoArgsLengthStart
    profinet_data[profinetIoArgsLengthIndex] = '0x' + format(profinetIoArgsLength, '08x')[0:2]
    profinet_data[profinetIoArgsLengthIndex+1] = '0x' + format(profinetIoArgsLength, '08x')[2:4]
    profinet_data[profinetIoArgsLengthIndex+2] = '0x' + format(profinetIoArgsLength, '08x')[4:6]
    profinet_data[profinetIoArgsLengthIndex+3] = '0x' + format(profinetIoArgsLength, '08x')[6:]

    # Assigning the correct Actual Count in Profinet IO Device (Read)
    profinetIoArgsLength = totalLengthEnd-profinetIoArgsLengthStart
    profinet_data[profinetIoActualCountIndex] = '0x' + format(profinetIoArgsLength, '08x')[0:2]
    profinet_data[profinetIoActualCountIndex+1] = '0x' + format(profinetIoArgsLength, '08x')[2:4]
    profinet_data[profinetIoActualCountIndex+2] = '0x' + format(profinetIoArgsLength, '08x')[4:6]
    profinet_data[profinetIoActualCountIndex+3] = '0x' + format(profinetIoArgsLength, '08x')[6:]

    # Assigning the correct Actual Count in Profinet IO Device (Read)
    IODReadResHeaderRecordDataLength = BlockLengthEnd - BlockLengthStart
    profinet_data[IODReadResHeaderRecordDataLengthIndex] = '0x' + format(IODReadResHeaderRecordDataLength, '08x')[0:2]
    profinet_data[IODReadResHeaderRecordDataLengthIndex+1] = '0x' + format(IODReadResHeaderRecordDataLength, '08x')[2:4]
    profinet_data[IODReadResHeaderRecordDataLengthIndex+2] = '0x' + format(IODReadResHeaderRecordDataLength, '08x')[4:6]
    profinet_data[IODReadResHeaderRecordDataLengthIndex+3] = '0x' + format(IODReadResHeaderRecordDataLength, '08x')[6:]

    # Assigning the correct RealIdentificationData BlockLength: 36 (0x0024)
    # This is Minus 4 because The block length includes everything in the block except the block type and itself which is 4 bytes
    IODReadResHeaderRecordDataLength = (BlockLengthEnd - BlockLengthStart) - 4
    profinet_data[BlockLengthIndex] = '0x' + format(IODReadResHeaderRecordDataLength, '04x')[0:2]
    profinet_data[BlockLengthIndex + 1] = '0x' + format(IODReadResHeaderRecordDataLength, '04x')[2:4]
    print(IODReadResHeaderRecordDataLength)



    # Since the function returns a list, relevant checksum bits are re-assigned the correct values.
    profinet_data[24] = calculate_IP_checksum(profinet_data[14:34])[0]
    profinet_data[25] = calculate_IP_checksum(profinet_data[14:34])[1]



    # Assuming the IP header length is always 20 bytes, the UDP length is then:
    # IP length minus 20.
    UDP_length = ip_length -20
    print(UDP_length)
    profinet_data[38] = '0x' + (hex(UDP_length)[2:].zfill(4))[:2]
    profinet_data[39] = '0x' + (hex(UDP_length)[2:].zfill(4))[2:]

    # Since the UDP header is always 8 bytes, the UDP payload minus the header, meaning
    # the DCE/ RPC length would be Length - 8.
    # This length does not need to be assigned.
    DCE_RPC_Length = UDP_length - 8

    # Assigning correct fragment length value
    fragmentLength = fragment_length_end_marker-fragment_length_start_marker
    profinet_data[dceRpcFragLenIndex] = '0x' + (hex(fragmentLength)[2:].zfill(4))[:2]
    profinet_data[dceRpcFragLenIndex+1] = '0x' + (hex(fragmentLength)[2:].zfill(4))[2:]

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




    # # dce_fragment_length = (len(profinet_data)-(14+20+8+80))
    # dce_fragment_length = fragment_length_end_marker - fragment_length_start_marker
    # profinet_data[116] = '0x' + format(dce_fragment_length, '04x')[0:2]
    # profinet_data[117] = '0x' + format(dce_fragment_length, '04x')[2:]

    print(f"{calculated_checksum:04x}")

    with open('PDIRGlobalData.txt', 'w') as f:
        for i in range(0, len(profinet_data), 8):
            f.write(', '.join(profinet_data[i:i + 8]) + ',\n')
    # Now, remove the last comma and newline
    with open('PDIRGlobalData.txt', 'rb+') as f:  # note the mode 'rb+'
        f.seek(-2, 2)  # go to 3 bytes from the end, endline,
        f.truncate()  # truncate the file at this point, effectively removing the last 2 bytes








# Parse the pcap file and get the dataframes


#

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    Print_C_String()
    print('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
# IP Version and Headerlength refer to the same hexadecimal value
# Flag and Fragment offset overlap for the first byte








#
#
#