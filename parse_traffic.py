import json
import os
import sys
import math, statistics
import matplotlib.pyplot as plt

remote = "162.254.193.5"
port = "27031"

class Stream:
    def __init__(self, ip="127.0.0.1"):
        self.ip = ip
        self.flow = []

    def __iter__(self):
        self.i = 0
        return self

    def __next__(self):
        cur = self.i
        self.i += 1
        if cur < len(self.flow):
            return self.flow[cur]
        else:
            raise StopIteration

    def __len__(self):
        return len(self.flow)

    def __getitem__(self, key):
        return self.flow[key]

    def parse(self, fn):
        data = []
        udp_count = 0
        tcp_count = 0
        other_count = 0
        with open(fn, 'r') as fp:
            data = json.load(fp)
        for i in data:
            e = i["_source"]["layers"]
            if "ip" not in list(e.keys()):
                other_count += 1
                continue
            if e["frame"]['frame.protocols'] == "eth:ethertype:ip:udp:data":
                self.flow.append(Packet(e["frame"]['frame.time_epoch'],
                                        e["ip"]['ip.src'],
                                        e["ip"]['ip.dst'],
                                        "udp",
                                        e["udp"]['udp.srcport'],
                                        e["udp"]['udp.dstport'],
                                        e["data"]['data.data']
                                        ))
                udp_count += 1
            elif e["frame"]['frame.protocols'] == "eth:ethertype:ip:tcp":
                self.flow.append(Packet(e["frame"]['frame.time_epoch'],
                                        e["ip"]['ip.src'],
                                        e["ip"]['ip.dst'],
                                        "tcp",
                                        e["tcp"]['tcp.srcport'],
                                        e["tcp"]['tcp.dstport'],
                                        ""
                                        ))
                tcp_count += 1
            else:
                other_count += 1
        print("Finished Parsing")
        print("Total:",udp_count+tcp_count+other_count)
        print("UDP:",udp_count)
        print("TCP:",tcp_count)
        print("Others:",other_count)

class Packet:
    def __init__(self, time_stamp, src, dst, protocol, src_port, dst_port, data):
        self.time_stamp = time_stamp
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = data

    def match(self, p):
        return self.data == p.data

def get_stat(l):
    """
    get max, min, median, mean, std
    """
    std = statistics.stdev(l)
    max = max(l)
    min = min(l)
    med = statistics.median(l)
    avg = statistics.mean(l)

    return {"max":max,"min":min,"median":med,"average":avg,"std":std}

def generate_flow_size(s, ip):
    upstream = {}
    downstream = {}
    up_total_size = 0
    up_total_count = 0
    down_total_size = 0
    down_total_count = 0
    for p in s:
        # key = int(float(p.time_stamp))
        key = float(p.time_stamp)
        if p.src == ip:
            # downstream
            try:
                downstream[key] -= len(p.data)
            except:
                downstream[key] = -len(p.data)
                upstream[key] = 0
            down_total_size += len(p.data)
            down_total_count  += 1
        if p.dst == ip:
            # upstream
            try:
                upstream[key] += len(p.data)
            except:
                upstream[key] = len(p.data)
                downstream[key] = 0
            up_total_size += len(p.data)
            up_total_count  += 1

    print("Upstream average: " + str(up_total_size / up_total_count))
    print("Downstream average: " + str(down_total_size / down_total_count))

    return upstream, downstream

def generate_flow_count(s, ip):
    upstream = {}
    downstream = {}
    for p in s:
        # key = int(float(p.time_stamp))
        key = float(p.time_stamp)
        if p.src == ip:
            # downstream
            try:
                downstream[key] -= 1
            except:
                downstream[key] = -1
                upstream[key] = 0
        if p.dst == ip:
            # upstream
            try:
                upstream[key] += 1
            except:
                upstream[key] = 1
                downstream[key] = 0

    return upstream, downstream

def plot_flow_size(client, client_high, source, source_high):
    up_c, down_c = generate_flow_size(client, client_high)
    up_s, down_s = generate_flow_size(source, source_high)

    x_data_c = list(up_c.keys())
    y_up_c = list(up_c.values())
    y_down_c = list(down_c.values())

    x_data_s = list(up_s.keys())
    y_up_s = list(up_s.values())
    y_down_s = list(down_s.values())

    fig, axs = plt.subplots(2)

    x_lim = [x_data_s[0], x_data_c[-1]]

    axs[0].plot(x_data_c, y_up_c, label="Upstream", linestyle='--')
    axs[0].plot(x_data_c, y_down_c, label="Downstream")
    axs[0].plot(x_data_c, [0]*len(x_data_c), linestyle=':')

    axs[0].set_title("Time Series on Client side")
    axs[0].set_xlabel('Time Stamps')
    axs[0].set_xlim(x_lim)
    axs[0].set_ylabel('Traffic Size\nDownstream (negative) | Upstream(positive)')
    axs[0].legend()

    axs[1].plot(x_data_s, y_up_s, label="Upstream")
    axs[1].plot(x_data_s, y_down_s, label="Downstream", linestyle='--')
    axs[1].plot(x_data_s, [0]*len(x_data_s), linestyle=':')

    axs[1].set_title("Time Series on Source side")
    axs[1].set_xlabel('Time Stamps')
    axs[1].set_xlim(x_lim)
    axs[1].set_ylabel('Traffic Size\nDownstream (negative) | Upstream(positive)')
    axs[1].legend()

    plt.show()

def plot_flow_count(client, client_high, source, source_high):
    up_c, down_c = generate_flow_count(client, client_high)
    up_s, down_s = generate_flow_count(source, source_high)

    x_data_c = list(up_c.keys())
    y_up_c = list(up_c.values())
    y_down_c = list(down_c.values())

    x_data_s = list(up_s.keys())
    y_up_s = list(up_s.values())
    y_down_s = list(down_s.values())

    fig, axs = plt.subplots(2)

    x_lim = [x_data_s[0], x_data_c[-1]]

    axs[0].plot(x_data_c, y_up_c, label="Upstream", linestyle='--')
    axs[0].plot(x_data_c, y_down_c, label="Downstream")
    axs[0].plot(x_data_c, [0]*len(x_data_c), linestyle=':')

    axs[0].set_title("Time Series on Client side")
    axs[0].set_xlabel('Time Stamps')
    axs[0].set_xlim(x_lim)
    axs[0].set_ylabel('Traffic Size\nDownstream (negative) | Upstream(positive)')
    axs[0].legend()

    axs[1].plot(x_data_s, y_up_s, label="Upstream")
    axs[1].plot(x_data_s, y_down_s, label="Downstream", linestyle='--')
    axs[1].plot(x_data_s, [0]*len(x_data_s), linestyle=':')

    axs[1].set_title("Time Series on Source side")
    axs[1].set_xlabel('Time Stamps')
    axs[1].set_xlim(x_lim)
    axs[1].set_ylabel('Traffic Size\nDownstream (negative) | Upstream(positive)')
    axs[1].legend()

    plt.show()

latency = []

p_c = Stream("10.0.0.39")
p_c.parse("data/Client_0718_SinglePlayer.json")

p_s = Stream("10.0.0.215")
p_s.parse("data/Source_0718_SinglePlayer.json")

client_count = {}
for c in p_c:
    try:
        if c.src == p_c.ip:
            client_count[c.dst] += 1
        if c.dst == p_c.ip:
            client_count[c.src] += 1
    except:
        if c.src == p_c.ip:
            client_count[c.dst] = 1
        if c.dst == p_c.ip:
            client_count[c.src] = 1

source_count = {}
for s in p_s:
    try:
        if s.src == p_s.ip:
            source_count[s.dst] += 1
        if s.dst == p_s.ip:
            source_count[s.src] += 1
    except:
        if s.src == p_s.ip:
            source_count[s.dst] = 1
        if s.dst == p_s.ip:
            source_count[s.src] = 1

# get the highest count as target of interest
h_c = sorted(client_count.items(), key=lambda x:x[1], reverse=True)[0]
h_s = sorted(source_count.items(), key=lambda x:x[1], reverse=True)[0]

plot_flow_size(p_c, h_c[0], p_s, h_s[0])
plot_flow_count(p_c, h_c[0], p_s, h_s[0])
