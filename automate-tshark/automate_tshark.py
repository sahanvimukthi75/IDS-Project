import os
import time
import requests
import pandas as pd
import json
from datetime import datetime
from collections import defaultdict


def parse_json_to_csv(json_file, csv_file):
    try:
        with open(json_file, encoding='utf-8') as f:
            packets = json.load(f)
    except UnicodeDecodeError:
        with open(json_file, encoding='utf-8', errors='ignore') as f:
            packets = json.load(f)
    except Exception as e:
        print(f"Failed to load JSON: {e}")
        return False

    flows = defaultdict(list)

    for pkt in packets:
        try:
            layers = pkt['_source']['layers']
            frame = layers.get('frame', {})
            ip = layers.get('ip', {})
            tcp = layers.get('tcp', {})

            if not frame or not ip or not tcp:
                continue

            src_ip = ip.get("ip.src", "")
            dst_ip = ip.get("ip.dst", "")
            src_port = tcp.get("tcp.srcport", "0")
            dst_port = tcp.get("tcp.dstport", "0")
            proto = ip.get("ip.proto", "0")
            timestamp = float(frame.get("frame.time_epoch", 0.0))
            pkt_len = int(frame.get("frame.len", 0))

            flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
            flows[flow_id].append({
                "timestamp": timestamp,
                "pkt_len": pkt_len,
                "tcp": tcp,
                "frame": frame
            })

        except Exception:
            continue

    records = []

    for flow_id, pkts in flows.items():
        if len(pkts) < 2:
            continue

        timestamps = [pkt["timestamp"] for pkt in pkts]
        pkt_lens = [pkt["pkt_len"] for pkt in pkts]
        timestamps.sort()

        flow_duration = (timestamps[-1] - timestamps[0]) * 1e6  # microseconds
        iat_list = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
        iat_mean = sum(iat_list) / len(iat_list) if iat_list else 0

        idle_times = [iat for iat in iat_list if iat > 1.0]
        idle_mean = sum(idle_times) / len(idle_times) if idle_times else 0

        active_times = []
        active_period = 0
        for iat in iat_list:
            if iat > 1.0:
                if active_period > 0:
                    active_times.append(active_period)
                    active_period = 0
            else:
                active_period += iat
        if active_period > 0:
            active_times.append(active_period)
        active_mean = sum(active_times) / len(active_times) if active_times else 0

        sample_pkt = pkts[0]
        record = {
            # exact order for ML model
            "Src Port": int(sample_pkt["tcp"].get("tcp.srcport", 0)),
            "Dst Port": int(sample_pkt["tcp"].get("tcp.dstport", 0)),
            "Protocol": int(sample_pkt["tcp"].get("tcp.stream", 0)),  # fallback to stream as ID
            "Flow Duration": flow_duration,
            "Tot Fwd Pkts": len(pkts),
            "Tot Bwd Pkts": 0,
            "Pkt Len Mean": sum(pkt_lens) / len(pkt_lens),
            "Flow Byts/s": (sum(pkt_lens) / (flow_duration / 1e6)) if flow_duration > 0 else 0,
            "Flow Pkts/s": (len(pkts) / (flow_duration / 1e6)) if flow_duration > 0 else 0,
            "SYN Flag Cnt": sum(int(pkt["tcp"].get("tcp.flags.syn", 0)) for pkt in pkts),
            "Init Fwd Win Byts": int(sample_pkt["tcp"].get("tcp.window_size_value", 0)),
            "ACK Flag Cnt": sum(int(pkt["tcp"].get("tcp.flags.ack", 0)) for pkt in pkts),
            "RST Flag Cnt": sum(int(pkt["tcp"].get("tcp.flags.reset", 0)) for pkt in pkts),
            "Flow IAT Mean": iat_mean,
            "Active Mean": active_mean,
            "Idle Mean": idle_mean
        }

        records.append(record)

    if records:
        df = pd.DataFrame(records)
        df.to_csv(csv_file, index=False)
        return True
    return False


def capture_to_model():
    while True:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_file = f"capture_{timestamp}.json"
            csv_file = f"features_{timestamp}.csv"

            print(f"[{timestamp}] Capturing 10 seconds of traffic...")
            os.system(f'tshark -i 5 -a duration:10 -T json > {json_file}')

            if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
                print("Parsing JSON to CSV...")
                if parse_json_to_csv(json_file, csv_file):
                    print("Sending to model...")
                    with open(csv_file, 'rb') as f:
                        res = requests.post("http://localhost:5000/predict", files={"file": f})
                        print("Model Response:", res.text)
                    os.remove(csv_file)
                else:
                    print("No valid packets parsed.")
                os.remove(json_file)
            else:
                print("No traffic captured or file empty.")
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(10)


if __name__ == "__main__":
    print("📡 Starting continuous capture and prediction...")
    capture_to_model()
