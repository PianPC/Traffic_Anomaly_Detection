from scapy.all import rdpcap
import os
import pickle
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import argparse

import csv
import re


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
    for key, flow in flows.items():
        if len(flow) >= min_packets:
            packet_lengths = [int(pkt[0]) for pkt in flow]  # 转换为 float
            time_deltas = [0.0] + [float(flow[i][1] - flow[i-1][1]) for i in range(1, len(flow))]  # 转换为 float
            filtered_flows.append({
                "flow_key": key,
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
                        futures.append(executor.submit(process_file, file_path, file, min_packets))

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


def filter_csv_columns(input_file, output_file):
    # 读取输入文件并确定要保留的列
    with open(input_file, 'r') as infile:
        reader = csv.reader(infile)
        headers = [col.strip().lower() for col in next(reader)]  # 去除空格并转为小写

        # 查找目标列的索引
        try:
            flow_id_idx = headers.index('flow id')
            label_idx = headers.index('label')
        except ValueError:
            # 如果标准名称找不到，尝试其他可能的变体
            flow_id_idx = next((i for i, h in enumerate(headers)
                              if re.fullmatch(r'flow[_\-]?id', h, re.I)), -1)
            label_idx = next((i for i, h in enumerate(headers)
                            if re.fullmatch(r'label', h, re.I)), -1)

            if flow_id_idx == -1 or label_idx == -1:
                raise ValueError("无法在CSV头部找到'flow_id'和'Label'列")

        # 写入输出文件
        with open(output_file, 'w', newline='') as outfile:
            writer = csv.writer(outfile)

            # 写入新的头部
            writer.writerow(['Flow ID', 'Label'])

            # 处理每一行数据
            for row in reader:
                # 获取flow_id和label，并去除label可能的前后空格
                flow_id = row[flow_id_idx]
                label = row[label_idx].strip()
                writer.writerow([flow_id, label])


def match_flow_ids_to_labels(json_dir, csv_file, output_dir):
    """
    将JSON文件中的flow_id与CSV文件中的Label进行匹配，并将结果保存到新的JSON文件中

    Args:
        json_dir: 包含JSON文件的目录路径
        csv_file: 包含flow_id和Label的CSV文件路径
        output_dir: 输出目录路径
    """
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 1. 从CSV文件中读取flow_id和Label的映射关系
    flow_id_to_label = {}
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            flow_id = row['Flow ID'].strip()
            label = row['Label'].strip()
            flow_id_to_label[flow_id] = label

    print(f"从CSV中加载了 {len(flow_id_to_label)} 个flow_id-Label映射")

    # 2. 处理每个JSON文件
    for json_file in os.listdir(json_dir):
        if not json_file.endswith('.json'):
            continue

        input_path = os.path.join(json_dir, json_file)
        output_path = os.path.join(output_dir, json_file)

        print(f"处理文件: {input_path}")

        # 读取JSON文件
        with open(input_path, 'r') as f:
            flows = json.load(f)

        # 为每个flow添加Label
        matched_count = 0
        unmatched_count = 0

        for flow in flows:
            # 从flow_key中提取flow_id
            # flow_key格式: (src_ip, dst_ip, src_port, dst_port, protocol)
            flow_key = flow['flow_key']
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key

            # 构建flow_id (格式应与CSV中的一致)
            flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

            # 查找匹配的Label
            if flow_id in flow_id_to_label:
                flow['label'] = flow_id_to_label[flow_id]
                matched_count += 1
            else:
                # 尝试反向flow_id (交换源和目的)
                reverse_flow_id = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{protocol}"
                if reverse_flow_id in flow_id_to_label:
                    flow['label'] = flow_id_to_label[reverse_flow_id]
                    matched_count += 1
                else:
                    flow['label'] = 'UNKNOWN'
                    unmatched_count += 1

        print(f"匹配结果: {matched_count} 个匹配, {unmatched_count} 个未匹配")

        # 保存带有Label的JSON文件
        with open(output_path, 'w') as f:
            json.dump(flows, f, indent=4)

        print(f"结果已保存到: {output_path}\n")


def classify_and_clean_flows(input_dir, output_dir):
    """
    根据label自动分类存储flows，并移除flow_key字段

    Args:
        input_dir: 包含输入JSON文件的目录
        output_dir: 输出目录，分类后的JSON文件将存储在这里
    """
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 初始化分类字典
    classified_flows = defaultdict(list)

    # 统计信息
    total_flows = 0
    label_counts = defaultdict(int)

    # 处理每个输入JSON文件
    for json_file in os.listdir(input_dir):
        if not json_file.endswith('.json'):
            continue

        input_path = os.path.join(input_dir, json_file)

        print(f"处理文件: {input_path}")

        # 读取JSON文件
        with open(input_path, 'r') as f:
            flows = json.load(f)

        # 分类每个flow并清理数据
        for flow in flows:
            total_flows += 1
            label = flow['label'].strip()

            # 创建清理后的flow对象
            cleaned_flow = {
                "packet_length": flow["packet_length"],
                "arrive_time_delta": flow["arrive_time_delta"]
            }

            # 添加到分类字典
            classified_flows[label].append(cleaned_flow)
            label_counts[label] += 1

    # 保存分类结果到不同的JSON文件
    for label, flows in classified_flows.items():
        # 创建安全的文件名（替换特殊字符）
        safe_label = "".join(c if c.isalnum() else "_" for c in label)
        output_file = f"{safe_label}.json"
        output_path = os.path.join(output_dir, output_file)

        with open(output_path, 'w') as f:
            json.dump(flows, f, indent=2)  # 使用缩进2使文件更紧凑

        print(f"已保存 {len(flows)} 个 '{label}' flows 到 {output_path}")

    # 打印统计信息
    print("\n分类统计:")
    print(f"总共处理了 {total_flows} 个 flows")
    for label, count in sorted(label_counts.items()):
        print(f"{label}: {count} flows")

    # 保存标签统计信息
    stats_path = os.path.join(output_dir, "label_statistics.json")
    with open(stats_path, 'w') as f:
        json.dump(dict(label_counts), f, indent=4)
    print(f"\n标签统计信息已保存到 {stats_path}")



def process_pcap_file(originaldata, inputcsv, dataset):

    dataset_directory = originaldata
    output_directory_step1 = f'temp/step1'
    min_flow_packets = 1                       # 设置最小数据包个数
    num_workers = 10  # 设置进程池中的最大工作进程数
    # 处理数据集
    process_dataset(dataset_directory, output_directory_step1, min_flow_packets, num_workers)

    # 将csv文件中的flow_id和label提取出来，并去除label可能的前后空格
    input_csv = inputcsv
    output_csv = 'temp/with_flow_id.csv'
    filter_csv_columns(input_csv, output_csv)

    # 将json的flow_id与output_csv的flow_id进行匹配，将flow_id对应的Label添加到json中
    json_directory = output_directory_step1  # 包含原始JSON文件的目录
    csv_file = output_csv  # 包含flow_id和Label的CSV文件
    output_directory_step2 = 'temp/step2'  # 输出目录
    match_flow_ids_to_labels(json_directory, csv_file, output_directory_step2)

    # 对添加上Label的json进行处理，首先，根据label添加到相应的json中，比如DDoS.json，Bot.json，Normal.json，这些json存放在dataset/train_data_test中
    input_directory = output_directory_step2  # 包含带有Label的JSON文件的目录
    output_directory_step3 = dataset  # 分类后的JSON文件输出目录
    classify_and_clean_flows(
        input_dir=input_directory,
        output_dir=output_directory_step3
    )


if __name__ == "__main__":

    # # 将一个文件夹中多个pcap处理成json格式，json中包含flow_id、packet_length、arrive_time_delta
    # dataset_directory = 'originaldata/train_data_'  # 替换为您的数据集路径
    # output_directory = 'dataset/train_data_history'         # 替换为您想要保存结果的路径
    # min_flow_packets = 1                       # 设置最小数据包个数
    # num_workers = 10  # 设置进程池中的最大工作进程数
    # # 处理数据集
    # process_dataset(dataset_directory, output_directory, min_flow_packets, num_workers)

    # # 将csv文件中的flow_id和label提取出来，并去除label可能的前后空格
    # input_csv = 'output/Wednesday-WorkingHours.csv'
    # output_csv = 'output/Wednesday-WorkingHours-flow_id_label.csv'
    # filter_csv_columns(input_csv, output_csv)

    # # 将json的flow_id与output_csv的flow_id进行匹配，将flow_id对应的Label添加到json中
    # json_directory = 'dataset/Thursday'  # 包含原始JSON文件的目录
    # csv_file = 'output/Thursday-WorkingHours-flow_id_label.csv'  # 包含flow_id和Label的CSV文件
    # output_directory = 'dataset/Thursday_with_labels'  # 输出目录
    # match_flow_ids_to_labels(json_directory, csv_file, output_directory)

    # 对添加上Label的json进行处理，首先，根据label添加到相应的json中，比如DDoS.json，Bot.json，Normal.json，这些json存放在dataset/train_data_test中
    input_directory = 'dataset/Friday_with_labels'  # 包含带有Label的JSON文件的目录
    output_directory = 'dataset/Friday_data_test'  # 分类后的JSON文件输出目录
    classify_and_clean_flows(
        input_dir=input_directory,
        output_dir=output_directory
    )

    # main()
