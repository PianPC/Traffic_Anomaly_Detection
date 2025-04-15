from scapy.all import rdpcap
import os
import pickle
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

def extract_flows(pcap_file, min_packets=20):
    """
    按照流提取数据包长度序列
    流的定义：五元组 (src_ip, dst_ip, src_port, dst_port, protocol)

    Args:
        pcap_file: pcap文件路径
        min_packets: 流中最小数据包个数，小于此数量的流将被过滤
    """
    print("正在处理"+pcap_file)
    packets = rdpcap(pcap_file)
    flows = defaultdict(list)

    for packet in packets:
        if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
            # 获取IP层信息
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto

            # 获取传输层信息
            if 'TCP' in packet:
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
            else:  # UDP
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport

            # 获取时间戳
            timestamp = packet.time

            # 确保源IP小于目的IP，以统一双向流的键
            if src_ip < dst_ip:
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                length = len(packet)
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
                length = -len(packet)  # 负值表示反向

            flows[flow_key].append((length, timestamp))

    # 筛选长度大于等于min_packets的流
    filtered_flows = []
    for flow in flows.values():
        if len(flow) >= min_packets:
            packet_lengths = [int(pkt[0]) for pkt in flow]  # 转换为 float
            time_deltas = [0.0] + [float(flow[i][1] - flow[i-1][1]) for i in range(1, len(flow))]  # 转换为 float
            filtered_flows.append({
                "packet_length": packet_lengths,
                "arrive_time_delta": time_deltas
            })

    return filtered_flows

def process_file(file_path, label_dir, min_packets):
    """
    处理单个文件并返回提取的流和标签
    """
    try:
        # 提取流
        flows = extract_flows(file_path, min_packets)
        labels = [label_dir] * len(flows)
        print(f"从 {file_path} 中提取了 {len(flows)} 个有效流")
        return flows, labels
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {str(e)}")
        return [], []

def process_dataset(dataset_dir, output_dir, min_packets=20, num_workers=None):
    """
    处理数据集并保存结果

    Args:
        dataset_dir: 数据集目录路径
        output_dir: 输出目录路径
        min_packets: 流中最小数据包个数
        num_workers: 进程池中的最大工作进程数
    """
    flow_data = defaultdict(list)  # 存储每个标签的流数据

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 使用进程池进行多进程处理
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []

        # 遍历数据集目录
        for label_dir in os.listdir(dataset_dir):
            label_path = os.path.join(dataset_dir, label_dir)
            if os.path.isdir(label_path):
                print(f"处理标签: {label_dir}")

                for file in os.listdir(label_path):
                    if file.endswith(('.pcap', '.pcapng')):
                        file_path = os.path.join(label_path, file)
                        print(f"提交文件到进程池: {file}")
                        futures.append(executor.submit(process_file, file_path, label_dir, min_packets))

        # 收集结果
        for future in as_completed(futures):
            flows, file_labels = future.result()
            for flow, label in zip(flows, file_labels):
                flow_data[label].append(flow)

    # 保存结果到JSON文件
    for label, data in flow_data.items():
        json_path = os.path.join(output_dir, f'{label}.json')
        print(f"保存流数据到: {json_path}")
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=4)

    print(f"\n处理完成:")
    print(f"总共提取了 {len(flow_data)} 个有效流")
    print(f"每个流至少包含 {min_packets} 个数据包")
    print(f"\n标签统计:")
    from collections import Counter
    for label, count in Counter(file_labels).items():
        print(f"{label}: {count}")

if __name__ == "__main__":
    # 设置参数
    dataset_directory = 'originaldata\\train_data_history'  # 替换为您的数据集路径
    output_directory = 'dataset\\train_data_history'         # 替换为您想要保存结果的路径
    min_flow_packets = 1                       # 设置最小数据包个数
    num_workers = 20  # 设置进程池中的最大工作进程数

    # 处理数据集
    process_dataset(dataset_directory, output_directory, min_flow_packets, num_workers)
