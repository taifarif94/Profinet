#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <pcap.h>

// Function to convert an array of hexadecimal bytes to raw binary data
std::vector<uint8_t> hexToRawData(const uint8_t *hexData, size_t dataSize)
{
    std::vector<uint8_t> rawData;
    for (size_t i = 0; i < dataSize; ++i)
    {
        rawData.push_back(hexData[i]);
    }
    return rawData;
}

int main()
{
    // Replace the hexData with the actual hexadecimal bytes
    uint8_t hexData[] = {0xa0, 0x36, 0x9f, 0x31, 0xa7, 0x2e, 0x00, 0xa0,
0x45, 0xd5, 0x37, 0xca, 0x08, 0x00, 0x45, 0x00,
0x00, 0xcc, 0x17, 0x5b, 0x40, 0x00, 0x40, 0x11,
0xa1, 0x2a, 0xc0, 0xa8, 0x00, 0x32, 0xc0, 0xa8,
0x00, 0x19, 0xeb, 0xb0, 0xc0, 0x15, 0x00, 0xb8,
0xb7, 0x0d, 0x04, 0x02, 0x20, 0x00, 0x00, 0x00,
0x00, 0x00, 0xde, 0xa0, 0x00, 0x00, 0x6c, 0x97,
0x11, 0xd1, 0x82, 0x71, 0x00, 0x01, 0x00, 0x01,
0x01, 0x74, 0xde, 0xa0, 0x00, 0x01, 0x6c, 0x97,
0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42,
0xdf, 0x7d, 0xfa, 0x60, 0x15, 0x15, 0x32, 0x29,
0x46, 0xf3, 0xb6, 0xe0, 0xa6, 0x38, 0x0a, 0x58,
0x38, 0x07, 0x5d, 0x61, 0x78, 0x39, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02,
0xff, 0xff, 0xff, 0xff, 0x00, 0x60, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x4c, 0x00, 0x01, 0x03, 0x6c, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x80, 0x09,
0x00, 0x3c, 0x01, 0x00, 0x00, 0x04, 0xe3, 0xf0,
0x22, 0xb4, 0x5a, 0xcc, 0x41, 0xa1, 0xbe, 0x98,
0x40, 0xe3, 0x00, 0xb9, 0xc0, 0x71, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
0xc0, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11,
0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x01};
    size_t dataSize = sizeof(hexData);

    std::vector<uint8_t> rawData = hexToRawData(hexData, dataSize);

    // Specify the output .pcap file name
    const char *pcapFileName = "output_FiberOpticDiagnosisInfo.pcap";

    pcap_t *pcap;
    pcap_dumper_t *pcapDump;

    // Open the output .pcap file for writing
    pcap = pcap_open_dead(DLT_EN10MB, 65535); // DLT_EN10MB is Ethernet
    pcapDump = pcap_dump_open(pcap, pcapFileName);

    // Write the packet to the .pcap file
    struct pcap_pkthdr header;
    header.ts.tv_sec = 0;
    header.ts.tv_usec = 0;
    header.caplen = header.len = rawData.size();
    pcap_dump((uint8_t *)pcapDump, &header, rawData.data());

    // Close the .pcap file and cleanup
    pcap_dump_close(pcapDump);
    pcap_close(pcap);

    std::cout << "PCAP file '" << pcapFileName << "' created successfully!" << std::endl;
    return 0;
}
