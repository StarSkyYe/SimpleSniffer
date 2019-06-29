#conding:utf-8

from scapy.all import *
import os
import collections
import sys
import queue
import xml.etree.cElementTree
import xml.parsers.expat

Net = collections.namedtuple("Net", ["src", "sport", "dst", "dport"])

class Packet_captor:
    def __init__(self, file_path = None, filter="", count=10, keepalive=True):
        self.file_path = file_path
        self.filter = filter
        self.pkt_count = count
        self._caping = False
        self.pkts = defaultdict(list)
        self.using_keepalive_pkt = keepalive

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
            return

        if "UDP" not in pkt:
            return

        if "Raw" not in pkt:
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

        if os.path.exists(self.file_path) == False:
            os.mkdir(self.file_path)

        for name, pkt in self.pkts.items():
            filename = "{0.src}_{0.sport}-{0.dst}_{0.dport}.pcap".format(name)
            file = os.path.join(self.file_path, filename)
            wrpcap(file, pkt)

def load_sniff_conf(filename):
    captors = []
    try:
        sniffer_conf_tree = xml.etree.cElementTree.parse(filename)
    except (EnvironmentError, xml.parsers.expat.ExpatError) as err:
        print("{0}: import sniff conf open error:{1}".format(os.path.basename(sys.argv[0]), err))
        return []
    for captor in sniffer_conf_tree.findall("captor"):
        try:
            data = {}
            data["count"] = int(captor.get("pkts_count"))
            data["keepalive"] = bool(int(captor.get("enable_keepalive_pkt")))
            filter = captor.find("filter").text
            data["filter"] = filter.strip() if filter is not None else ""
            file_path = captor.find("pcap_store_path").text
            data["file_path"] = file_path.strip() if file_path is not None else ""
            captors.append(data)
        except (ValueError, LookupError) as err:
            print("{0}:import sniffer conf error:{1}".format(os.path.basename(sys.argv[0]), err))
            return []
    return captors

class Worker(threading.Thread):
    def __init__(self, work_queue):
        super().__init__()
        self.work_queue = work_queue

    def run(self):
        try:
            captor = self.work_queue.get()
            sniff(prn=captor.parse_pcap_packet, started_callback=captor.start_caping,
                  stop_filter=captor.stop_caping, store=False)
            captor.dump_pkts()
        finally:
            self.work_queue.task_done()

def main():
    if len(sys.argv) >= 2:
        print("usage: {0} [conf_file]".format(sys.argv[0]))
        exit(0)

    conf_file = "sniff_conf.xml"
    if len(sys.argv) == 2:
        conf_file = sys.argv[1]

    captors_conf = load_sniff_conf(conf_file)
    if len(captors_conf) <= 0:
        print("load conf failed, path:{0}".format(conf_file))
        exit(-1)

    captors = []
    work_queue = queue.Queue()
    for i in range(len(captors_conf)):
        worker = Worker(work_queue)
        worker.daemon = True
        worker.start()

    for elemtent in captors_conf:
        captor = Packet_captor(**elemtent)
        captors.append(captor)
        work_queue.put(captor)

    while True:
        stop = input("If you want to stop, enter stop:")
        if stop.lower() == "stop":
            for captor in captors:
                captor.caping = False
            break
    work_queue.join()

if __name__ == '__main__':
    main()

