This Python script generates a raw Ethernet II frame for a ProfiNet protocol over UDP/IP (User Datagram Protocol over Internet Protocol). 

1. It imports required modules: `pandas`, `collections.defaultdict`, `struct`, and `socket`.

2. The two functions, `calculate_IP_checksum` and `calculate_checksum_UDP`, compute the checksums for the IP and UDP headers respectively. 

3. The function `Print_C_String` that constructs the Ethernet II, IP, UDP, and DCE/RPC (Distributed Computing Environment / Remote Procedure Call) packet headers and ProfiNet data. It has the MAC addresses, IP addresses, ports, lengths, checksums, and the ProfiNet data hard-coded. 

   - It creates a list `profinet_data` that sequentially contains the hexadecimal values of all the header fields and the ProfiNet data.

   - It updates the length field in the IP header, which depends on the length of the total data (minus the Ethernet II header length).

   - It updates the checksum field in the IP header using the `calculate_IP_checksum` function.

   - It also updates the length field in the UDP header, which depends on the length of the IP packet (minus the IP header length).

   - It then calculates the UDP checksum using the `calculate_checksum_UDP` function and updates the UDP checksum field.

   - It then calculates the length of DCE/RPC data and adjusts the DCE/RPC length field in the header.

   - Finally, it writes the entire constructed packet (with all headers and data) into a text file named `ms.txt`.

Filter: (ip.dst && dcerpc.ver)