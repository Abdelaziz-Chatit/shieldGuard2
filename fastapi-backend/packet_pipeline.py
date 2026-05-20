import json
import os
import time
import sqlite3
import threading
import traceback
from pathlib import Path
from datetime import datetime

import requests

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    sniff = None
    IP = TCP = UDP = None

try:
    import pickle
except ImportError:
    pickle = None

BACKEND_DIR = Path(__file__).resolve().parent
DB_PATH = BACKEND_DIR / 'shieldguard.db'
FEATURES_PATH = BACKEND_DIR / 'models' / 'isolation_forest' / 'features.pkl'
STATUS_PATH = BACKEND_DIR / 'pipeline_status.json'
API_URL = 'http://127.0.0.1:8000/predict_network'
FLOW_TIMEOUT_SECONDS = 5
STATUS_INTERVAL_SECONDS = 1

flow_states = {}
flow_lock = threading.Lock()
total_packets = 0
start_time = time.time()


def load_feature_names():
    if not FEATURES_PATH.exists() or pickle is None:
        return []
    try:
        with open(FEATURES_PATH, 'rb') as f:
            features = pickle.load(f)
        if isinstance(features, list):
            return features
    except Exception:
        pass
    return []

FEATURE_NAMES = load_feature_names()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                score REAL,
                is_suspicious INTEGER,
                label_text TEXT,
                raw_features_json TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def current_timestamp():
    return datetime.utcnow().isoformat()


def calculate_stats(lengths):
    if not lengths:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    total = sum(lengths)
    count = len(lengths)
    mean = total / count if count else 0.0
    variance = sum((x - mean) ** 2 for x in lengths) / count if count else 0.0
    std = variance ** 0.5
    return mean, std, variance, min(lengths), max(lengths)


def build_features(state):
    features = {name: 0.0 for name in FEATURE_NAMES}
    if not state:
        return features

    duration = max(0.001, state['last_seen'] - state['first_seen'])
    total_pkts = state['fwd_pkts'] + state['bwd_pkts']
    total_bytes = state['fwd_bytes'] + state['bwd_bytes']

    fwd_mean_len, fwd_std_len, _, fwd_min_len, fwd_max_len = calculate_stats(state.get('fwd_lengths', []))
    bwd_mean_len, bwd_std_len, _, bwd_min_len, bwd_max_len = calculate_stats(state.get('bwd_lengths', []))
    pkt_mean_len, pkt_std_len, pkt_var_len, pkt_min_len, pkt_max_len = calculate_stats(state.get('packet_lengths', []))
    fwd_header_mean = sum(state.get('fwd_header_lengths', [])) / max(1, len(state.get('fwd_header_lengths', [])))
    bwd_header_mean = sum(state.get('bwd_header_lengths', [])) / max(1, len(state.get('bwd_header_lengths', [])))

    features['Destination_Port'] = state.get('dst_port') or 0
    features['Flow_Duration'] = duration
    features['Total_Fwd_Packets'] = state['fwd_pkts']
    features['Total_Backward_Packets'] = state['bwd_pkts']
    features['Total_Length_of_Fwd_Packets'] = float(state['fwd_bytes'])
    features['Total_Length_of_Bwd_Packets'] = float(state['bwd_bytes'])
    features['Fwd_Packet_Length_Max'] = float(fwd_max_len)
    features['Fwd_Packet_Length_Min'] = float(fwd_min_len)
    features['Fwd_Packet_Length_Mean'] = float(fwd_mean_len)
    features['Fwd_Packet_Length_Std'] = float(fwd_std_len)
    features['Bwd_Packet_Length_Max'] = float(bwd_max_len)
    features['Bwd_Packet_Length_Min'] = float(bwd_min_len)
    features['Bwd_Packet_Length_Mean'] = float(bwd_mean_len)
    features['Bwd_Packet_Length_Std'] = float(bwd_std_len)
    features['Flow_Bytes_s'] = float(total_bytes) / duration
    features['Flow_Packets_s'] = float(total_pkts) / duration
    features['Flow_IAT_Mean'] = float(state.get('flow_iat_total', 0.0)) / max(1, state.get('flow_iat_count', 0))
    features['Flow_IAT_Std'] = 0.0
    features['Flow_IAT_Max'] = float(state.get('flow_iat_max', 0.0))
    features['Flow_IAT_Min'] = float(state.get('flow_iat_min', 0.0)) if state.get('flow_iat_count', 0) else 0.0
    features['Fwd_IAT_Total'] = float(state.get('fwd_iat_total', 0.0))
    features['Fwd_IAT_Mean'] = float(state.get('fwd_iat_total', 0.0)) / max(1, state.get('fwd_iat_count', 0))
    features['Fwd_IAT_Std'] = 0.0
    features['Fwd_IAT_Max'] = float(state.get('fwd_iat_max', 0.0))
    features['Fwd_IAT_Min'] = float(state.get('fwd_iat_min', 0.0)) if state.get('fwd_iat_count', 0) else 0.0
    features['Bwd_IAT_Total'] = float(state.get('bwd_iat_total', 0.0))
    features['Bwd_IAT_Mean'] = float(state.get('bwd_iat_total', 0.0)) / max(1, state.get('bwd_iat_count', 0))
    features['Bwd_IAT_Std'] = 0.0
    features['Bwd_IAT_Max'] = float(state.get('bwd_iat_max', 0.0))
    features['Bwd_IAT_Min'] = float(state.get('bwd_iat_min', 0.0)) if state.get('bwd_iat_count', 0) else 0.0
    features['Fwd_PSH_Flags'] = float(state.get('fwd_psh_flags', 0))
    features['Bwd_PSH_Flags'] = float(state.get('bwd_psh_flags', 0))
    features['Fwd_URG_Flags'] = float(state.get('fwd_urg_flags', 0))
    features['Bwd_URG_Flags'] = float(state.get('bwd_urg_flags', 0))
    features['Fwd_Header_Length'] = float(fwd_header_mean)
    features['Bwd_Header_Length'] = float(bwd_header_mean)
    features['Fwd_Packets_s'] = float(state['fwd_pkts']) / duration
    features['Bwd_Packets_s'] = float(state['bwd_pkts']) / duration
    features['Min_Packet_Length'] = float(pkt_min_len)
    features['Max_Packet_Length'] = float(pkt_max_len)
    features['Packet_Length_Mean'] = float(pkt_mean_len)
    features['Packet_Length_Std'] = float(pkt_std_len)
    features['Packet_Length_Variance'] = float(pkt_var_len)
    features['FIN_Flag_Count'] = float(state.get('fin_count', 0))
    features['SYN_Flag_Count'] = float(state.get('syn_count', 0))
    features['RST_Flag_Count'] = float(state.get('rst_count', 0))
    features['PSH_Flag_Count'] = float(state.get('psh_count', 0))
    features['ACK_Flag_Count'] = float(state.get('ack_count', 0))
    features['URG_Flag_Count'] = float(state.get('urg_count', 0))
    features['CWE_Flag_Count'] = float(state.get('cwe_flag_count', 0))
    features['ECE_Flag_Count'] = float(state.get('ece_flag_count', 0))
    features['Down_Up_Ratio'] = float(state['bwd_bytes']) / max(1.0, float(state['fwd_bytes']))
    features['Average_Packet_Size'] = float(total_bytes) / max(1, total_pkts)
    features['Avg_Fwd_Segment_Size'] = float(state['fwd_bytes']) / max(1, state['fwd_pkts'])
    features['Avg_Bwd_Segment_Size'] = float(state['bwd_bytes']) / max(1, state['bwd_pkts'])
    features['Fwd_Header_Length.1'] = float(fwd_header_mean)
    features['Init_Win_bytes_forward'] = float(state.get('init_win_bytes_forward') or 0)
    features['Init_Win_bytes_backward'] = float(state.get('init_win_bytes_backward') or 0)
    features['act_data_pkt_fwd'] = float(state.get('act_data_pkt_fwd', 0))
    features['min_seg_size_forward'] = float(state.get('min_seg_size_forward') or 0)
    return features


def store_event(event):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO network_events (timestamp, src_ip, dst_ip, dst_port, protocol, score, is_suspicious, label_text, raw_features_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event['timestamp'], event['src_ip'], event['dst_ip'], event.get('dst_port'), event.get('protocol'), event.get('score'), int(event.get('is_suspicious', False)), event.get('label_text'), json.dumps(event.get('raw_features_json', {}))
            )
        )
        conn.commit()
    finally:
        conn.close()


def post_predict_network(features):
    try:
        payload = {'features': features}
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None


def flush_flow(key):
    global total_packets
    with flow_lock:
        state = flow_states.pop(key, None)
    if not state:
        return

    features = build_features(state)
    result = post_predict_network(features)
    if result is None:
        return

    event = {
        'timestamp': current_timestamp(),
        'src_ip': state['src_ip'],
        'dst_ip': state['dst_ip'],
        'dst_port': state['dst_port'],
        'protocol': state['protocol'],
        'score': result.get('score'),
        'is_suspicious': bool(result.get('is_suspicious', False)),
        'label_text': result.get('label_text'),
        'raw_features_json': features
    }
    store_event(event)
    total_packets += state['fwd_pkts'] + state['bwd_pkts']


def prune_flows():
    while True:
        now = time.time()
        expired = []
        with flow_lock:
            for key, state in list(flow_states.items()):
                if now - state['last_seen'] > FLOW_TIMEOUT_SECONDS:
                    expired.append(key)
        for key in expired:
            try:
                flush_flow(key)
            except Exception:
                traceback.print_exc()
        time.sleep(1)


def update_status():
    while True:
        uptime = int(time.time() - start_time)
        status = {
            'running': True,
            'packets_captured': total_packets,
            'uptime_seconds': uptime,
            'packets_per_second': round(total_packets / max(1, uptime), 2),
            'last_updated': current_timestamp()
        }
        try:
            with open(STATUS_PATH, 'w', encoding='utf-8') as f:
                json.dump(status, f)
        except Exception:
            pass
        time.sleep(STATUS_INTERVAL_SECONDS)


def process_packet(packet):
    if IP is None:
        return
    if not packet.haslayer(IP):
        return
    ip = packet[IP]
    proto = packet.proto
    src_ip = ip.src
    dst_ip = ip.dst
    src_port = None
    dst_port = None
    direction = 'fwd'

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        return

    key = (src_ip, dst_ip, src_port, dst_port, proto)
    packet_len = len(packet)
    now = time.time()

    with flow_lock:
        state = flow_states.get(key)
        if state is None:
            state = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': 'tcp' if proto == 6 else 'udp' if proto == 17 else str(proto),
                'first_seen': now,
                'last_seen': now,
                'fwd_pkts': 0,
                'bwd_pkts': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_max_len': 0,
                'bwd_max_len': 0,
                'fwd_min_len': float('inf'),
                'bwd_min_len': float('inf'),
                'min_len': float('inf'),
                'max_len': 0,
                'packet_lengths': [],
                'fwd_lengths': [],
                'bwd_lengths': [],
                'fwd_header_lengths': [],
                'bwd_header_lengths': [],
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'bwd_urg_flags': 0,
                'fin_count': 0,
                'syn_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'ack_count': 0,
                'urg_count': 0,
                'cwe_flag_count': 0,
                'ece_flag_count': 0,
                'init_win_bytes_forward': None,
                'init_win_bytes_backward': None,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': None,
                'flow_iat_total': 0.0,
                'flow_iat_count': 0,
                'flow_iat_max': 0.0,
                'flow_iat_min': float('inf'),
                'fwd_iat_total': 0.0,
                'fwd_iat_count': 0,
                'fwd_iat_max': 0.0,
                'fwd_iat_min': float('inf'),
                'bwd_iat_total': 0.0,
                'bwd_iat_count': 0,
                'bwd_iat_max': 0.0,
                'bwd_iat_min': float('inf'),
                'last_fwd_seen': None,
                'last_bwd_seen': None,
            }
            flow_states[key] = state

        # Use direction by source IP and port ordering
        packet_flags = None
        header_len = None
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_flags = tcp_layer.flags
            header_len = tcp_layer.dataofs * 4 if hasattr(tcp_layer, 'dataofs') else None
        elif packet.haslayer(UDP):
            header_len = 8

        if src_ip == state['src_ip'] and src_port == key[2]:
            direction = 'fwd'
            state['fwd_pkts'] += 1
            state['fwd_bytes'] += packet_len
            state['fwd_max_len'] = max(state['fwd_max_len'], packet_len)
            state['fwd_min_len'] = min(state['fwd_min_len'], packet_len)
            state['fwd_lengths'].append(packet_len)
            if header_len is not None:
                state['fwd_header_lengths'].append(header_len)
            if state['init_win_bytes_forward'] is None and packet_flags is not None and packet.haslayer(TCP):
                state['init_win_bytes_forward'] = float(packet[TCP].window)
            if packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
                state['act_data_pkt_fwd'] += 1
                payload_len = len(packet[TCP].payload)
                if state['min_seg_size_forward'] is None or payload_len < state['min_seg_size_forward']:
                    state['min_seg_size_forward'] = payload_len
            if state['last_fwd_seen'] is not None:
                iat = now - state['last_fwd_seen']
                state['fwd_iat_total'] += iat
                state['fwd_iat_count'] += 1
                state['fwd_iat_max'] = max(state['fwd_iat_max'], iat)
                state['fwd_iat_min'] = min(state['fwd_iat_min'], iat)
                state['flow_iat_total'] += iat
                state['flow_iat_count'] += 1
                state['flow_iat_max'] = max(state['flow_iat_max'], iat)
                state['flow_iat_min'] = min(state['flow_iat_min'], iat)
            state['last_fwd_seen'] = now
            if packet_flags is not None:
                if packet_flags & 0x08:
                    state['fwd_psh_flags'] += 1
                if packet_flags & 0x20:
                    state['fwd_urg_flags'] += 1
        else:
            direction = 'bwd'
            state['bwd_pkts'] += 1
            state['bwd_bytes'] += packet_len
            state['bwd_max_len'] = max(state['bwd_max_len'], packet_len)
            state['bwd_min_len'] = min(state['bwd_min_len'], packet_len)
            state['bwd_lengths'].append(packet_len)
            if header_len is not None:
                state['bwd_header_lengths'].append(header_len)
            if state['init_win_bytes_backward'] is None and packet_flags is not None and packet.haslayer(TCP):
                state['init_win_bytes_backward'] = float(packet[TCP].window)
            if state['last_bwd_seen'] is not None:
                iat = now - state['last_bwd_seen']
                state['bwd_iat_total'] += iat
                state['bwd_iat_count'] += 1
                state['bwd_iat_max'] = max(state['bwd_iat_max'], iat)
                state['bwd_iat_min'] = min(state['bwd_iat_min'], iat)
                state['flow_iat_total'] += iat
                state['flow_iat_count'] += 1
                state['flow_iat_max'] = max(state['flow_iat_max'], iat)
                state['flow_iat_min'] = min(state['flow_iat_min'], iat)
            state['last_bwd_seen'] = now
        state['packet_lengths'].append(packet_len)
        state['min_len'] = min(state['min_len'], packet_len)
        state['max_len'] = max(state['max_len'], packet_len)
        state['last_seen'] = now

        if packet_flags is not None:
            if packet_flags & 0x01:
                state['fin_count'] += 1
            if packet_flags & 0x02:
                state['syn_count'] += 1
            if packet_flags & 0x04:
                state['rst_count'] += 1
            if packet_flags & 0x08:
                state['psh_count'] += 1
            if packet_flags & 0x10:
                state['ack_count'] += 1
            if packet_flags & 0x20:
                state['urg_count'] += 1
            if packet_flags & 0x40:
                state['ece_flag_count'] += 1
            if packet_flags & 0x80:
                state['cwe_flag_count'] += 1


def run_capture():
    if sniff is None:
        print('Scapy is not installed. packet_pipeline cannot start.')
        return
    init_db()
    threading.Thread(target=prune_flows, daemon=True).start()
    threading.Thread(target=update_status, daemon=True).start()
    print('packet_pipeline started, capturing live packets...')
    try:
        sniff(prn=process_packet, store=False)
    except Exception as exc:
        print(f'packet_pipeline failed: {exc}')
        traceback.print_exc()


if __name__ == '__main__':
    run_capture()
