import os
import json
import pandas as pd
from scapy.all import rdpcap
import numpy as np
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataConverter:
    def __init__(self):
        # 使用项目根目录作为基础目录
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.original_dir = os.path.join(self.base_dir, 'originaldata')
        self.dataset_dir = os.path.join(self.base_dir, 'dataset')

        # 确保目录存在
        os.makedirs(self.original_dir, exist_ok=True)
        os.makedirs(self.dataset_dir, exist_ok=True)
        logger.info(f"原始数据目录: {self.original_dir}")
        logger.info(f"数据集目录: {self.dataset_dir}")

    def process_pcap(self, pcap_file):
        """处理PCAP文件，提取包长序列和到达时间间隔"""
        try:
            logger.info(f"开始处理PCAP文件: {pcap_file}")
            if not os.path.exists(pcap_file):
                logger.error(f"文件不存在: {pcap_file}")
                return []

            packets = rdpcap(pcap_file)
            logger.info(f"成功读取 {len(packets)} 个数据包")

            # 使用字典存储不同的流
            flows = {}

            for i, packet in enumerate(packets):
                try:
                    if 'IP' not in packet:
                        continue

                    # 获取五元组信息
                    src_ip = packet['IP'].src
                    dst_ip = packet['IP'].dst

                    # 获取端口信息（TCP或UDP）
                    if 'TCP' in packet:
                        src_port = packet['TCP'].sport
                        dst_port = packet['TCP'].dport
                        protocol = 'TCP'
                    elif 'UDP' in packet:
                        src_port = packet['UDP'].sport
                        dst_port = packet['UDP'].dport
                        protocol = 'UDP'
                    else:
                        continue

                    # 创建流标识符（使用五元组）
                    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                    reverse_flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

                    # 确定包的方向和长度
                    if flow_id in flows:
                        length = len(packet)  # 正向流
                    elif reverse_flow_id in flows:
                        length = -len(packet)  # 反向流
                        flow_id = reverse_flow_id
                    else:
                        length = len(packet)  # 新流，默认为正向

                    # 获取或创建流
                    if flow_id not in flows:
                        flows[flow_id] = {
                            'packet_length': [],
                            'arrive_time_delta': [],
                            'last_time': None
                        }

                    # 计算时间间隔
                    current_time = float(packet.time)
                    if flows[flow_id]['last_time'] is not None:
                        delta = current_time - flows[flow_id]['last_time']
                    else:
                        delta = 0
                    flows[flow_id]['last_time'] = current_time

                    # 添加到流中
                    flows[flow_id]['packet_length'].append(length)
                    flows[flow_id]['arrive_time_delta'].append(delta)

                except Exception as e:
                    logger.warning(f"处理第 {i} 个数据包时出错: {str(e)}")
                    continue

            # 转换为列表格式
            flow_list = []
            for flow_id, flow_data in flows.items():
                if len(flow_data['packet_length']) > 0:  # 只保留非空流
                    flow_list.append({
                        'packet_length': flow_data['packet_length'],
                        'arrive_time_delta': flow_data['arrive_time_delta']
                    })

            logger.info(f"处理完成: 提取了 {len(flow_list)} 个流")

            if len(flow_list) == 0:
                logger.error("没有提取到任何有效的流")
                return []

            return flow_list

        except Exception as e:
            logger.error(f"处理PCAP文件 {pcap_file} 时出错: {str(e)}", exc_info=True)
            return []

    def process_csv(self, csv_file):
        """处理CSV文件，提取包长序列和到达时间间隔"""
        try:
            df = pd.read_csv(csv_file)
            flows = []

            # 按流分组处理数据包
            current_flow = {
                'packet_length': [],
                'arrive_time_delta': []
            }

            for i, row in df.iterrows():
                # 获取包长（带方向）
                length = row['length'] * row['direction']
                current_flow['packet_length'].append(length)

                # 计算到达时间间隔
                if i > 0:
                    delta = float(row['timestamp']) - float(df.iloc[i-1]['timestamp'])
                else:
                    delta = 0
                current_flow['arrive_time_delta'].append(delta)

            # 将当前流添加到结果中
            if current_flow['packet_length']:
                flows.append(current_flow)

            logger.info(f"从 {csv_file} 中提取了 {len(flows)} 个流")
            return flows

        except Exception as e:
            logger.error(f"处理CSV文件 {csv_file} 时出错: {str(e)}")
            return []

    def process_directory(self, input_dir):
        """处理目录中的所有文件"""
        try:
            # 获取数据集名称（使用目录名）
            dataset_name = os.path.basename(input_dir)
            output_dir = os.path.join(self.dataset_dir, dataset_name)
            os.makedirs(output_dir, exist_ok=True)

            # 处理目录中的所有文件
            for filename in os.listdir(input_dir):
                input_path = os.path.join(input_dir, filename)
                if os.path.isfile(input_path):
                    logger.info(f"处理文件: {filename}")

                    # 根据文件类型选择处理方法
                    if filename.endswith('.pcap'):
                        flows = self.process_pcap(input_path)
                    elif filename.endswith('.csv'):
                        flows = self.process_csv(input_path)
                    else:
                        logger.warning(f"不支持的文件格式: {filename}")
                        continue

                    if flows:
                        # 生成输出文件名
                        output_filename = f"{os.path.splitext(filename)[0]}.json"
                        output_path = os.path.join(output_dir, output_filename)

                        # 保存处理后的数据
                        with open(output_path, 'w', encoding='utf-8') as f:
                            json.dump(flows, f, ensure_ascii=False, indent=2)

                        logger.info(f"已保存处理后的数据到: {output_path}")

            # 保存数据集信息
            info = {
                'name': dataset_name,
                'original_dir': input_dir,
                'processed_dir': output_dir,
                'process_time': datetime.now().isoformat(),
                'file_count': len(os.listdir(output_dir))
            }

            info_path = os.path.join(output_dir, 'info.json')
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(info, f, ensure_ascii=False, indent=2)

            logger.info(f"数据集 {dataset_name} 处理完成")

        except Exception as e:
            logger.error(f"处理目录 {input_dir} 时出错: {str(e)}")
            raise  # 重新抛出异常，让调用者知道处理失败

    def process_all(self):
        """处理originaldata目录下的所有数据集"""
        try:
            for dataset_name in os.listdir(self.original_dir):
                dataset_dir = os.path.join(self.original_dir, dataset_name)
                if os.path.isdir(dataset_dir):
                    logger.info(f"开始处理数据集: {dataset_name}")
                    self.process_directory(dataset_dir)

            logger.info("所有数据集处理完成")

        except Exception as e:
            logger.error(f"处理所有数据集时出错: {str(e)}")

if __name__ == '__main__':
    converter = DataConverter()
    converter.process_all()
