import pandas as pd
import numpy as np
from scapy.all import rdpcap
import os
import json
from datetime import datetime

class DataProcessor:
    def __init__(self, max_packet_length=100):
        self.max_packet_length = max_packet_length

    def process_packets(self, packets):
        """处理数据包，提取特征"""
        packet_lengths = []
        time_deltas = []
        last_time = None

        for packet in packets:
            # 提取包长度
            if hasattr(packet, 'len'):
                length = packet.len
            else:
                length = 0
            packet_lengths.append(length)

            # 计算时间间隔
            if hasattr(packet, 'time'):
                current_time = packet.time
                if last_time is not None:
                    delta = current_time - last_time
                    time_deltas.append(delta)
                last_time = current_time
            else:
                time_deltas.append(0)

        # 填充或截断到固定长度
        if len(packet_lengths) > self.max_packet_length:
            packet_lengths = packet_lengths[:self.max_packet_length]
            time_deltas = time_deltas[:self.max_packet_length]
        else:
            packet_lengths.extend([0] * (self.max_packet_length - len(packet_lengths)))
            time_deltas.extend([0] * (self.max_packet_length - len(time_deltas)))

        return {
            'packet_length': packet_lengths,
            'arrive_time_delta': time_deltas
        }

    def process_pcap(self, file_path):
        """处理PCAP文件"""
        packets = rdpcap(file_path)
        flows = []
        current_flow = []

        for packet in packets:
            if hasattr(packet, 'IP'):
                current_flow.append(packet)
                if len(current_flow) >= self.max_packet_length:
                    flows.append(self.process_packets(current_flow))
                    current_flow = []

        if current_flow:
            flows.append(self.process_packets(current_flow))

        return flows

    def process_csv(self, file_path):
        """处理CSV文件"""
        df = pd.read_csv(file_path)
        flows = []
        current_flow = []

        if 'length' in df.columns and 'time' in df.columns:
            for _, row in df.iterrows():
                packet = type('Packet', (), {
                    'len': row['length'],
                    'time': row['time']
                })
                current_flow.append(packet)
                if len(current_flow) >= self.max_packet_length:
                    flows.append(self.process_packets(current_flow))
                    current_flow = []

        if current_flow:
            flows.append(self.process_packets(current_flow))

        return flows

    def save_to_json(self, flows, output_dir, filename):
        """保存处理后的数据为JSON格式"""
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(flows, f, ensure_ascii=False, indent=2)
        return output_path

    def load_from_json(self, file_path):
        """从JSON文件加载数据"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
