import os
import time
import requests
import pandas as pd
import json
from datetime import datetime

def parse_json_to_csv(json_file, csv_file):
    try:
        with open(json_file, encoding='utf-8') as f:
            packets = json.load(f)
    except UnicodeDecodeError:
        print("⚠️ UTF-8 decode failed, trying with errors='ignore'...")
        with open(json_file, encoding='utf-8', errors='ignore') as f:
            packets = json.load(f)
    except Exception as e:
        print(f"🚨 Failed to load JSON: {e}")
        return False

    records = []

    for pkt in packets:
        try:
            layers = pkt['_source']['layers']
            tcp = layers.get('tcp', {})
            ip = layers.get('ip', {})
            frame = layers.get('frame', {})

            # Skip if essential values are missing
            if not tcp or not ip or not frame:
                raise ValueError("Missing TCP/IP/frame layer")

            record = {
                'Src Port': int(tcp.get('tcp.srcport', 0)),
                'Dst Port': int(tcp.get('tcp.dstport', 0)),
                'Protocol': int(ip.get('ip.proto', 0)),
                'Flow Duration': float(frame.get('frame.time_delta_displayed', 0.0)) * 1e6,  # microseconds
                'Tot Fwd Pkts': 1,  # Placeholder
                'Tot Bwd Pkts': 0,  # Placeholder
                'Pkt Len Mean': float(frame.get('frame.len', 0)),
                'Flow Byts/s': 0,  # Placeholder
                'Flow Pkts/s': 0,  # Placeholder
                'SYN Flag Cnt': int(tcp.get('tcp.flags.syn', 0)),
                'Init Fwd Win Byts': int(tcp.get('tcp.window_size_value', 0)),
                'ACK Flag Cnt': int(tcp.get('tcp.flags.ack', 0)),
                'RST Flag Cnt': int(tcp.get('tcp.flags.reset', 0)),
            }
            records.append(record)

        except Exception as e:
            print(f"Skipping a packet due to error: {e}")
            continue

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
                print("🔍 Parsing JSON to CSV...")
                if parse_json_to_csv(json_file, csv_file):
                    print("📡 Sending data to model...")
                    with open(csv_file, 'rb') as f:
                        res = requests.post("http://localhost:5000/predict", files={"file": f})
                        print("🔔 API Response:", res.text)

                    os.remove(csv_file)
                else:
                    print("⚠️ No valid packets parsed.")

                os.remove(json_file)
            else:
                print("❌ No traffic captured or file empty.")
        except Exception as e:
            print(f"🚨 Error: {e}")
        
        time.sleep(10)


if __name__ == "__main__":
    print("📡 Starting continuous capture and prediction...")
    capture_to_model()
