import argparse
import os
import sys 
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def process_pcap(fname):
    print(f'Opening {fname}')

    count = 0
    ipv4count = 0
    ipv6count = 0
    for (pkt_data, pkt_metadata) in RawPcapReader(fname):
        count += 1

        pkt = Ether(pkt_data)
        if 'type' not in pkt.fields:
            continue

        if pkt.type == 0x0800:
            ipv4count += 1
        else:
            ipv6count += 1

    print('{} contains {} packets'.format(fname, count))
    print('There are {} ipv4 packets and {} ipv6 packets'.format(ipv4count, ipv6count))
    
    #Calculating percentages and formatting to 2 decimal points
    ipv4percent = round((ipv4count / count * 100), 2)
    ipv6percent = round((ipv6count / count * 100), 2)
    

    print('The file is {}% ipv4 packets and {}% ipv6 packets'
          .format(ipv4percent, ipv6percent))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help ='pcap file to parse', required=True)
    args = parser.parse_args()

    fname = args.pcap
    if not os.path.isfile(fname):
        print(f'"{fname}" does not exist', file=sys.stderr)
        sys.exit(-1)

    process_pcap(fname)
    sys.exit(0)
