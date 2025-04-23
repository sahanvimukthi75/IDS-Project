import json
import pandas as pd
import numpy as np
from collections import defaultdict

def extract_flow_features(packets):
    """Process packet list into flow features"""
    if len(packets) < 2:
        return None  # Not a complete flowb hh5j
    
    # Time calculations
    timestamps = [float(p['_source']['layers']['frame']['frame.time_epoch']) 
                 for p in packets]
    duration = max(timestamps) - min(timestamps)
    
    # Directional analysis
    src_ip = packets[0]['_source']['layers']['ip']['ip.src']
    fwd_pkts = [p for p in packets 
               if p['_source']['layers']['ip']['ip.src'] == src_ip]
    bwd_pkts = [p for p in packets 
               if p['_source']['layers']['ip']['ip.src'] != src_ip]

    # Packet lengths
    fwd_lens = [int(p['_source']['layers']['frame']['frame.len']) 
               for p in fwd_pkts]
    bwd_lens = [int(p['_source']['layers']['frame']['frame.len']) 
               for p in bwd_pkts]

    # TCP flags
    flag_counts = {
        'FIN': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin'] == '1'),
        'SYN': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == '1'),
        'RST': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.reset'] == '1'),
        'PSH': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.push'] == '1'),
        'ACK': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] == '1'),
        'URG': sum(1 for p in packets 
                  if p['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.urg'] == '1')
    }

    return {
        'Flow ID': packets[0]['_source']['layers']['tcp']['tcp.stream'],
        'Src IP': src_ip,
        'Src Port': packets[0]['_source']['layers']['tcp']['tcp.srcport'],
        'Dst IP': packets[0]['_source']['layers']['ip']['ip.dst'],
        'Dst Port': packets[0]['_source']['layers']['tcp']['tcp.dstport'],
        'Protocol': packets[0]['_source']['layers']['frame']['frame.protocols'].split(':')[-1],
        'Timestamp': min(timestamps),
        'Flow Duration': duration,
        'Tot Fwd Pkts': len(fwd_pkts),
        'Tot Bwd Pkts': len(bwd_pkts),
        'Fwd Pkt Len Mean': np.mean(fwd_lens) if fwd_lens else 0,
        'Fwd Pkt Len Std': np.std(fwd_lens) if fwd_lens else 0,
        'FIN Flag Cnt': flag_counts['FIN'],
        'SYN Flag Cnt': flag_counts['SYN'],
        'PSH Flag Cnt': flag_counts['PSH'],
        'ACK Flag Cnt': flag_counts['ACK'],
        'Init Fwd Win Byts': int(packets[0]['_source']['layers']['tcp']['tcp.window_size_value']),
        'TLS_Length': int(packets[0]['_source']['layers']['tls']['tls.record']['tls.record.length']) 
                     if 'tls' in packets[0]['_source']['layers'] else 0
    }