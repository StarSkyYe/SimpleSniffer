#conding:utf-8

from scapy.all import *
import os
import collections

Net = collections.namedtuple("Net", "src", "sport", "dst", "dport")

class packet_captor:
    def __init__(self, file_path = None, filter="", count=10, keepavlie=True):
        self.file_path = file_path
        self.filter = filter
        self.pkt_count = count
        self._caping = False
        self.pkts = defaultdict(list)
        self.using_keepalive_pkt = keepavlie

    @property
    def caping(self):
        return self._caping
    @caping.setter
    def caping(self, value):
        self._caping = bool(value)

    def parse_pcap_packet(self, pkt):
        if not self.caping:
            return

        if "IP" not in pkt:
            print("Missing IP layer in pkt")
            return

        if "UDP" not in pkt:
            print("Missing UDP layer in pkt")
            return

        if "Raw" not in pkt:
            print("Missing Raw data in pkt")
            return

        try:
            rtpInfo = RTP(pkt["Raw"].load)
        except (Exception) as err:
            return

        net = Net(pkt["IP"].src, pkt["UDP"].sport, pkt["IP"].dst, pkt["UDP"].dport)
        if not self.using_keepalive_pkt and pkt["UDP"].len <= 12:
            return

        self.pkts[net].append(pkt)
        if len(self.pkts[net]) > self.pkt_count:
            self.pkts[net].pop(0)

    def start_caping(self):
        self.caping = True

    def stop_caping(self, pkt):
        if self.caping == False:
            return True

    def dump_pkts(self):
        if self.file_path is None:
            self.file_path = os.getcwd()
        for name, pkts in self.pkts.items():
            filename = "{0.src}_{0.sport}-{0.dst}_{0.dport}.pcap".format(name)
            wrpcap(filename, pkts)

captor = packet_captor()
t = sniff(prn=captor.parse_pcap_packet, started_callback=captor.start_caping,
          stop_filter=captor.stop_caping, store=False, count=300)
while True:
    stop = input("If want to stop, enter stop:")
    if stop.lower() == "stop":
        captor.caping = False
        break
captor.dump_pkts()
