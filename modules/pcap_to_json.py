from scapy.all import rdpcap
import os
import pickle
import json
from collections import defaultdict, Counter
from concurrent.futures import ProcessPoolExecutor, as_completed


def extract_flows(pcap_file, min_packets=20):
    """提取流数据（增强元数据）"""
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

            # 生成标准化flow_id（使用-作为分隔符）
            if src_ip < dst_ip:
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}({protocol})"
                direction = 1
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}({protocol})"
                direction = -1

            # 记录包数据
            flows[flow_id].append({
                'timestamp': float(packet.time),
                'length': len(packet) * direction,
                'direction': direction
            })

    # 转换为输出格式
    output_flows = []
    for flow_id, packets in flows.items():
        if len(packets) < min_packets:
            continue

        # 计算流统计信息
        packets.sort(key=lambda x: x['timestamp'])
        time_deltas = [0.0] + [
            packets[i]['timestamp'] - packets[i-1]['timestamp']
            for i in range(1, len(packets))
        ]

        # 统一使用-分割flow_id
        parts = flow_id.split('-')
        src_part = parts[0].split(':')
        dst_part = parts[1].split(':')

        output_flows.append({
            'flow_id': flow_id,
            'src_ip': src_part[0],
            'dst_ip': dst_part[0],
            'src_port': int(src_part[1]),
            'dst_port': int(dst_part[1].split('(')[0]),
            'protocol': protocol,
            'start_time': packets[0]['timestamp'],
            'end_time': packets[-1]['timestamp'],
            'duration': packets[-1]['timestamp'] - packets[0]['timestamp'],
            'total_bytes': sum(abs(p['length']) for p in packets),
            'packet_length': [p['length'] for p in packets],
            'arrive_time_delta': time_deltas
        })

    return output_flows

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

# def process_dataset(dataset_dir, output_dir, min_packets=20, num_workers=None):
#     """
#     处理数据集并保存结果

#     Args:
#         dataset_dir: 数据集目录路径
#         output_dir: 输出目录路径
#         min_packets: 流中最小数据包个数
#         num_workers: 进程池中的最大工作进程数
#     """
#     flow_data = defaultdict(list)  # 存储每个标签的流数据

#     # 确保输出目录存在
#     os.makedirs(output_dir, exist_ok=True)

#     # 使用进程池进行多进程处理
#     with ProcessPoolExecutor(max_workers=num_workers) as executor:
#         futures = []

#         # 遍历数据集目录
#         for label_dir in os.listdir(dataset_dir):
#             label_path = os.path.join(dataset_dir, label_dir)
#             if os.path.isdir(label_path):
#                 print(f"处理标签: {label_dir}")

#                 for file in os.listdir(label_path):
#                     if file.endswith(('.pcap', '.pcapng')):
#                         file_path = os.path.join(label_path, file)
#                         print(f"提交文件到进程池: {file}")
#                         futures.append(executor.submit(process_file, file_path, label_dir, min_packets))

#         # 收集结果
#         for future in as_completed(futures):
#             flows, file_labels = future.result()
#             for flow, label in zip(flows, file_labels):
#                 flow_data[label].append(flow)

#     # 保存结果到JSON文件
#     for label, data in flow_data.items():
#         json_path = os.path.join(output_dir, f'{label}.json')
#         print(f"保存流数据到: {json_path}")
#         with open(json_path, 'w') as f:
#             json.dump(data, f, indent=4)

#     print(f"\n处理完成:")
#     print(f"总共提取了 {len(flow_data)} 个有效流")
#     print(f"每个流至少包含 {min_packets} 个数据包")
#     print(f"\n标签统计:")
#     from collections import Counter
#     for label, count in Counter(file_labels).items():
#         print(f"{label}: {count}")

def process_dataset(dataset_dir, output_dir, min_packets=20, num_workers=None):
    """
    处理直接包含PCAP文件的目录（无子文件夹）
    使用文件名（不带扩展名）作为标签

    Args:
        dataset_dir: 包含PCAP文件的目录
        output_dir: 输出目录
        min_packets: 流的最小包数
        num_workers: 进程数
    """
    flow_data = defaultdict(list)  # 存储流数据，按标签分类
    all_labels = []  # 记录所有标签用于统计

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 使用进程池处理
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []

        # 直接遍历dataset_dir下的文件
        for file in os.listdir(dataset_dir):
            if file.lower().endswith(('.pcap', '.pcapng')):
                file_path = os.path.join(dataset_dir, file)
                # 使用文件名（不带扩展名）作为标签
                label = os.path.splitext(file)[0]
                print(f"提交文件到进程池: {file} (标签: {label})")
                futures.append(executor.submit(process_file, file_path, label, min_packets))

        # 收集结果
        for future in as_completed(futures):
            flows, labels = future.result()
            all_labels.extend(labels)
            for flow, label in zip(flows, labels):
                flow_data[label].append(flow)

    # 保存结果到JSON文件（每个标签单独文件）
    total_flows = 0
    for label, flows in flow_data.items():
        total_flows += len(flows)
        output_path = os.path.join(output_dir, f"{label}.json")
        with open(output_path, 'w') as f:
            json.dump(flows, f, indent=4)
        print(f"已保存 {len(flows)} 个流到 {output_path}")

    # 打印统计信息
    print(f"\n处理完成: 共提取 {total_flows} 个流")
    print("标签统计:", dict(Counter(all_labels)))

    return {'status': 'success', 'total_flows': total_flows}

if __name__ == "__main__":
    # 设置参数
    dataset_directory = 'originaldata\\train_data_history'  # 替换为您的数据集路径
    output_directory = 'dataset\\train_data_history'         # 替换为您想要保存结果的路径
    min_flow_packets = 1                       # 设置最小数据包个数
    num_workers = 20  # 设置进程池中的最大工作进程数

    # 处理数据集
    process_dataset(dataset_directory, output_directory, min_flow_packets, num_workers)
