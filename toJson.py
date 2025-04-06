import os
import json
import pandas as pd
import logging
from datetime import datetime
import multiprocessing
from tqdm import tqdm
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JsonConverter:
    def __init__(self, timestamp=None, model_type='fsnet'):
        # 设置基础目录
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_type = model_type

        # 如果指定了时间戳，使用指定的文件夹
        if timestamp:
            self.input_dir = os.path.join(self.base_dir, 'traindata', timestamp)
            self.output_dir = os.path.join(self.base_dir, 'dataset', timestamp)
        else:
            self.input_dir = os.path.join(self.base_dir, 'traindata')
            self.output_dir = os.path.join(self.base_dir, 'dataset')

        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"输入目录: {self.input_dir}")
        logger.info(f"输出目录: {self.output_dir}")
        logger.info(f"模型类型: {model_type}")

    def process_csv(self, csv_file):
        """处理CSV文件，提取包长序列和到达时间间隔"""
        try:
            # 尝试不同的编码方式读取文件
            encodings = ['utf-8', 'gbk', 'latin1']
            df = None
            for encoding in encodings:
                try:
                    df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                    break
                except UnicodeDecodeError:
                    continue

            if df is None:
                logger.error(f"无法读取文件 {csv_file}，尝试了所有编码方式")
                return {}

            # 检查必要的列是否存在
            if 'Label' not in df.columns:
                logger.error(f"文件 {csv_file} 缺少 Label 列")
                return {}

            # 按Label分组处理数据
            result = {}
            for label, group in df.groupby('Label'):
                flows = []
                for _, row in group.iterrows():
                    try:
                        # 根据模型类型处理数据
                        if self.model_type == 'fsnet':
                            # FS-Net需要包长序列和时间间隔
                            packet_length = []
                            if row['Total Fwd Packets'] > 0:
                                avg_fwd_length = row['Total Length of Fwd Packets'] / row['Total Fwd Packets']
                                packet_length.extend([avg_fwd_length] * int(row['Total Fwd Packets']))

                            if row['Total Backward Packets'] > 0:
                                avg_bwd_length = row['Total Length of Bwd Packets'] / row['Total Backward Packets']
                                packet_length.extend([-avg_bwd_length] * int(row['Total Backward Packets']))

                            # 计算时间间隔
                            arrive_time_delta = []
                            total_packets = len(packet_length)
                            if total_packets > 1:
                                avg_iat = row['Flow Duration'] / (total_packets - 1)
                                arrive_time_delta = [0] + [avg_iat] * (total_packets - 1)
                            else:
                                arrive_time_delta = [0]

                            if packet_length:
                                flows.append({
                                    'packet_length': packet_length,
                                    'arrive_time_delta': arrive_time_delta
                                })
                        elif self.model_type == 'df':
                            # DF模型需要其他特征
                            features = {
                                'duration': row['Flow Duration'],
                                'protocol': row['Protocol'],
                                'total_fwd_packets': row['Total Fwd Packets'],
                                'total_bwd_packets': row['Total Backward Packets'],
                                'total_length_of_fwd_packets': row['Total Length of Fwd Packets'],
                                'total_length_of_bwd_packets': row['Total Length of Bwd Packets'],
                                'fwd_packet_length_max': row['Fwd Packet Length Max'],
                                'fwd_packet_length_min': row['Fwd Packet Length Min'],
                                'fwd_packet_length_mean': row['Fwd Packet Length Mean'],
                                'fwd_packet_length_std': row['Fwd Packet Length Std'],
                                'bwd_packet_length_max': row['Bwd Packet Length Max'],
                                'bwd_packet_length_min': row['Bwd Packet Length Min'],
                                'bwd_packet_length_mean': row['Bwd Packet Length Mean'],
                                'bwd_packet_length_std': row['Bwd Packet Length Std'],
                                'flow_bytes_s': row['Flow Bytes/s'],
                                'flow_packets_s': row['Flow Packets/s'],
                                'flow_iat_mean': row['Flow IAT Mean'],
                                'flow_iat_std': row['Flow IAT Std'],
                                'flow_iat_max': row['Flow IAT Max'],
                                'flow_iat_min': row['Flow IAT Min']
                            }
                            flows.append(features)
                    except Exception as e:
                        logger.warning(f"处理行时出错: {str(e)}")
                        continue

                if flows:
                    result[label] = flows

            return result

        except Exception as e:
            logger.error(f"处理CSV文件 {csv_file} 时出错: {str(e)}")
            return {}

    def process_file(self, file_info):
        """处理单个文件"""
        filename, input_path = file_info
        logger.info(f"处理文件: {filename}")

        if filename.endswith('.csv'):
            result = self.process_csv(input_path)
        else:
            result = {}

        return result

    def process_files(self):
        """处理输入目录中的所有文件"""
        try:
            # 获取所有CSV文件
            files = [(f, os.path.join(self.input_dir, f))
                    for f in os.listdir(self.input_dir)
                    if f.endswith('.csv')]

            if not files:
                logger.warning(f"在目录 {self.input_dir} 中没有找到CSV文件")
                return

            # 使用多进程处理文件
            with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
                results = list(tqdm(pool.imap(self.process_file, files),
                                  total=len(files),
                                  desc="处理文件"))

            # 合并结果
            category_flows = {}
            for result in results:
                for label, flows in result.items():
                    if label not in category_flows:
                        category_flows[label] = []
                    category_flows[label].extend(flows)

            # 保存每个类别的JSON文件
            for category, flows in category_flows.items():
                output_file = os.path.join(self.output_dir, f"{category}.json")
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(flows, f, ensure_ascii=False, indent=2)
                logger.info(f"已保存 {category} 类别的数据到: {output_file}")

            logger.info("所有文件处理完成")

        except Exception as e:
            logger.error(f"处理文件时出错: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='处理CSV文件并生成JSON文件')
    parser.add_argument('--timestamp', type=str, help='时间戳文件夹名称')
    parser.add_argument('--model', type=str, default='fsnet', choices=['fsnet', 'df'],
                       help='模型类型：fsnet 或 df')
    args = parser.parse_args()

    converter = JsonConverter(args.timestamp, args.model)
    converter.process_files()

if __name__ == '__main__':
    main()
