#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP采样工具 - 从大文件中提取小样本
用法: python pcap_sampler.py input.pcap --output sample.pcap --method count --param 1000
"""

import argparse
from scapy.all import PcapReader, PcapWriter, wrpcap
import random
import time
import os

def sample_by_count(input_file, output_file, count):
    """按包数采样"""
    print(f"正在提取前 {count} 个包...")
    packets = []
    with PcapReader(input_file) as pcap:
        for i, pkt in enumerate(pcap):
            if i >= count:
                break
            packets.append(pkt)
    wrpcap(output_file, packets)
    print(f"已保存 {len(packets)} 个包到 {output_file}")

def sample_by_time(input_file, output_file, duration_sec):
    """按时间窗口采样"""
    print(f"正在提取 {duration_sec} 秒流量...")
    packets = []
    start_time = None
    with PcapReader(input_file) as pcap:
        for pkt in pcap:
            if not hasattr(pkt, 'time'):
                continue
            if start_time is None:
                start_time = pkt.time
            if pkt.time - start_time <= duration_sec:
                packets.append(pkt)
            else:
                break
    wrpcap(output_file, packets)
    print(f"已保存 {len(packets)} 个包 ({duration_sec}秒流量) 到 {output_file}")

def sample_random(input_file, output_file, percentage):
    """随机抽样"""
    print(f"正在随机抽取 {percentage}% 的包...")
    all_packets = []
    with PcapReader(input_file) as pcap:
        all_packets = list(pcap)  # 注意：大文件会消耗内存

    sample_size = int(len(all_packets) * percentage / 100)
    sampled = random.sample(all_packets, sample_size)
    wrpcap(output_file, sampled)
    print(f"已从 {len(all_packets)} 个包中随机抽取 {len(sampled)} 个包到 {output_file}")

def main():
    parser = argparse.ArgumentParser(description="PCAP采样工具")
    parser.add_argument("input", help="输入PCAP文件路径")
    parser.add_argument("--output", required=True, help="输出PCAP文件路径")
    parser.add_argument("--method", choices=["count", "time", "random"],
                        default="count", help="采样方法 (count/time/random)")
    parser.add_argument("--param", type=float, required=True,
                        help="采样参数 (包数/秒数/百分比)")

    args = parser.parse_args()

    # 检查输入文件
    if not os.path.exists(args.input):
        print(f"错误：输入文件 {args.input} 不存在")
        return

    # 执行采样
    try:
        if args.method == "count":
            sample_by_count(args.input, args.output, int(args.param))
        elif args.method == "time":
            sample_by_time(args.input, args.output, args.param)
        elif args.method == "random":
            sample_random(args.input, args.output, args.param)
    except Exception as e:
        print(f"采样失败: {str(e)}")
        if "Magic" in str(e):
            print("提示：可能是文件格式不兼容，尝试用Wireshark转换为标准PCAP格式")

if __name__ == "__main__":
    main()
    # 提取前N个包
    # python split.py large.pcap --output sample.pcap --method count --param 1000
    # python split.py "C:\Users\PPCa1\Desktop\friday\Friday-WorkingHours.pcap" --output "C:\Users\PPCa1\Desktop\test\test.pcap" --method count --param 1000

    # 提取前N秒流量
    # python split.py "C:\Users\PPCa1\Desktop\friday\Friday-WorkingHours.pcap" --output "E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\originaldata\test" --method time --param 60

    # 按百分比随机
    # python split.py "C:\Users\PPCa1\Desktop\friday\Friday-WorkingHours.pcap" --output "C:\Users\PPCa1\Desktop\test\test.pcap" --method random --param 1
