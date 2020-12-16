Emmanouil Petrakos 2014030009

All requested functionality has been implemented except part 11.

9) Yes. In TCP, if the next expected sequence number is greater than the current sequence number, the packet is a retransmission.

10) No. In UDP if a packet get lost/corrupted, the sender is not informed about it. If they cannot know about it's state,
they cannot retransmit it. Underlying protocols build upon UDP on application level can serve this functionality,
but for the UDP protocol the retransmission is not the same packet.

--------------------------------------------------------------------------------------------------
HOW TO USE

./monitor [-i -r -h] <network interface/packet capture file>

option -i monitors live a network interface until a SIGINT signal appears (Ctrl+C).

option -e read a pcap file

For both options, the program prints packet info and on exit the requested statistics.


--------------------------------------------------------------------------------------------------
TESTING

Tested mostly with the given test_pcap_5mins.pcap file. Output seems to match Wireshark.

The test_pcap_5mins.pcap doesn't include any IPv6 packets and I can't enable IPv6 in my interface.
I couldn't really test it, but I believe the program works with it.
