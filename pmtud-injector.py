#!/usr/bin/env python3

# Copyright (c) 2019 Star Brilliant
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import expiringdict
import functools
import ipaddress
import logging
import scapy.all
import sys
from typing import *

IPv4_BROADCAST = ipaddress.IPv4Address('255.255.255.255')


class Rule:
    def __init__(self, src: Union[ipaddress.IPv4Network, ipaddress.IPv6Network], dst: Union[ipaddress.IPv4Network, ipaddress.IPv6Network], mtu: int, trigger: int) -> None:
        self.src = src
        self.dst = dst
        self.mtu = mtu
        self.trigger = trigger

    def match(self, src: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], dst: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        return src in self.src and dst in self.dst

    def mtu_upperbound(self, src: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], dst: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], previous_mtu: Optional[int], previous_trigger: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
        if src in self.src and dst in self.dst:
            return self.mtu if previous_mtu is None else min(self.mtu, previous_mtu), self.trigger if previous_trigger is None else min(self.mtu, previous_trigger)
        return previous_mtu, previous_trigger


def print_usage(program_name: str) -> None:
    print('Usage: {} config_file'.format(program_name))
    print()
    print('Configuration file format:')
    print('    iface  <INTERFACE NAME>')
    print('    filter <LIBPCAP FILTER>')
    print('    cache  <CACHE ITEMS> <CACHE SECONDS>')
    print('    <SRC CIDR 1> <DST CIDR 1> <MTU 1> [ <TRIGGER LENGTH 1> ]')
    print('    <SRC CIDR 2> <DST CIDR 2> <MTU 2> [ <TRIGGER LENGTH 2> ]')


def generate_reply(rules: List[Rule], pmtud_cache: MutableMapping[str, None], packet: scapy.packet.Packet, iface: str) -> Optional[scapy.packet.Packet]:
    mtu, trigger = None, None  # type: Tuple[Optional[int], Optional[int]]
    if isinstance(packet, scapy.layers.inet.IP):
        if packet.src in pmtud_cache:
            return None
        if packet.proto == 1 and packet.payload.type not in (0, 8):
            return None
        src = ipaddress.IPv4Address(packet.src)
        dst = ipaddress.IPv4Address(packet.dst)
        if src.is_multicast or src == IPv4_BROADCAST:
            return None
        for rule in rules:
            mtu, trigger = rule.mtu_upperbound(src, dst, mtu, trigger)
        raw_packet = bytes(packet)
        if mtu is not None and trigger is not None and trigger < min(len(raw_packet), packet.len):
            logging.info('{} -{}\u2192 {} MTU {}'.format(packet.src, iface or '', packet.dst, mtu))
            reply = scapy.layers.inet.IP(id=packet.id, ttl=64, dst=packet.src) / scapy.layers.inet.ICMP(type=3, code=4, nexthopmtu=mtu) / raw_packet[:28]
            pmtud_cache[packet.src] = None
            return reply
    elif isinstance(packet, scapy.layers.inet6.IPv6):
        if packet.src in pmtud_cache:
            return None
        if packet.nh == 58 and packet.payload.type < 128:
            return None
        src = ipaddress.IPv6Address(packet.src)
        dst = ipaddress.IPv6Address(packet.dst)
        if src.is_multicast:
            return None
        for rule in rules:
            mtu, trigger = rule.mtu_upperbound(src, dst, mtu, trigger)
        raw_packet = bytes(packet)
        if mtu is not None and trigger is not None and trigger < len(raw_packet):
            logging.info('{} -{}\u2192 {} MTU {}'.format(packet.src, iface or '', packet.dst, mtu))
            reply = scapy.layers.inet6.IPv6(hlim=64, dst=packet.src) / scapy.layers.inet6.ICMPv6PacketTooBig(mtu=mtu) / raw_packet[:max(mtu - 48, 1232)]
            pmtud_cache[packet.src] = None
            return reply
    return None


def callback(rules: List[Rule], pmtud_cache: MutableMapping[str, None], packet: scapy.packet.Packet) -> Optional[str]:
    iface = packet.sniffed_on
    if isinstance(packet, scapy.layers.l2.Ether):
        reply = generate_reply(rules, pmtud_cache, packet.payload, iface)
    elif isinstance(packet, (scapy.layers.inet.IP, scapy.layers.inet6.IPv6)):
        reply = generate_reply(rules, pmtud_cache, packet, iface)
    elif packet.payload is not None:
        reply = generate_reply(rules, pmtud_cache, packet.payload, iface)
    else:
        return None
    if reply is not None:
        try:
            scapy.sendrecv.send(reply, verbose=False, iface=iface)
        except Exception as e:
            logging.error('Error sending packet: {}'.format(e))
    return None


def main(argv: List[str]) -> int:
    logging.basicConfig(format='[%(asctime)s] %(message)s', level=logging.INFO)
    if len(argv) != 2:
        print_usage(argv[0])
        return 0
    cache_items, cache_seconds = 1024, 10
    ifaces = []  # type: List[str]
    bpf = None  # type: Optional[str]
    rules = []  # type: List[Rule]
    with open(argv[1], 'r') as config_file:
        for lineno, line in enumerate(config_file):
            fields = line.split('#', 1)[0].strip().split()
            if len(fields) == 0:
                continue
            if fields[0] == 'iface':
                if len(fields) != 2:
                    logging.error('Error in line {}: {}'.format(lineno + 1, line))
                    return 1
                ifaces.append(fields[1])
            elif fields[0] == 'filter':
                bpf = ' '.join(fields[1:])
            elif fields[0] == 'cache':
                if len(fields) != 3:
                    logging.error('Error in line {}: {}'.format(lineno + 1, line))
                    return 1
                try:
                    cache_items = int(fields[1])
                    if cache_items <= 0:
                        raise ValueError('Cache items should be greater than 0')
                    cache_seconds = int(fields[2])
                    if cache_seconds <= 0:
                        raise ValueError('Cache seconds should be greater than 0')
                except Exception as e:
                    logging.error('Error in line {}: {}'.format(lineno + 1, e))
                    return 1
            else:
                if len(fields) not in (3, 4):
                    logging.error('Error in line {}: {}'.format(lineno + 1, line))
                try:
                    src = ipaddress.ip_network(fields[0])
                    dst = ipaddress.ip_network(fields[1])
                    mtu = int(fields[2])
                    if mtu <= 0:
                        raise ValueError('MTU should be greater than 0')
                    trigger = mtu
                    if len(fields) >= 4:
                        trigger = int(fields[3])
                        if trigger < 0:
                            raise ValueError('Trigger length should be greater or equal than 0')
                except Exception as e:
                    logging.error('Error in line {}: {}'.format(lineno + 1, e))
                    return 1
                rules.append(Rule(src, dst, mtu, trigger))
    if 'any' in ifaces:
        ifaces = []

    pmtud_cache = expiringdict.ExpiringDict(max_len=cache_items, max_age_seconds=cache_seconds)

    try:
        scapy.sendrecv.sniff(prn=functools.partial(callback, rules, pmtud_cache), promisc=False, filter=bpf, iface=ifaces or None)
    except Exception as e:
        logging.error('Error sniffing packets: {}'.format(e))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
