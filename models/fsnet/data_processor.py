import pandas as pd
import numpy as np
from scapy.all import rdpcap
import os

class DataProcessor:
    def __init__(self):
        self.max_packet_length = 100

    def process_pcap(self, file_path):
        """处理PCAP文件"""
        packets = rdpcap(file_path)
        flows = []

        # 按源IP和目的IP分组
        current_flow = []
        for packet in packets:
            if hasattr(packet, 'IP'):
                current_flow.append(packet)
                if len(current_flow) >= self.max_packet_length:
                    flows.append(current_flow)
                    current_flow = []

        if current_flow:
            flows.append(current_flow)

        return flows

    def process_csv(self, file_path):
        """处理CSV文件"""
        df = pd.read_csv(file_path)
        flows = []

        # 假设CSV文件包含包长度列
        if 'length' in df.columns:
            current_flow = []
            for length in df['length']:
                current_flow.append(length)
                if len(current_flow) >= self.max_packet_length:
                    flows.append(current_flow)
                    current_flow = []

            if current_flow:
                flows.append(current_flow)

        return flows

    def analyze_flows(self, flows, model_predictor):
        """分析流量"""
        results = {
            'normal_flows': 0,
            'anomaly_flows': 0,
            'anomaly_types': {
                'DDoS': 0,
                '扫描': 0,
                '注入': 0
            }
        }

        for flow in flows:
            prediction = model_predictor.predict(flow)
            if prediction == 0:
                results['normal_flows'] += 1
            else:
                results['anomaly_flows'] += 1
                # 这里可以添加更详细的异常类型判断
                results['anomaly_types']['DDoS'] += 1

        return results
