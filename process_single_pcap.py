import os
import json
import logging
from data_processor import DataConverter
from tqdm import tqdm
from datetime import datetime
from scapy.all import rdpcap

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_single_pcap(pcap_path):
    """
    处理单个PCAP文件并显示进度
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(pcap_path):
            logger.error(f"文件不存在: {pcap_path}")
            return None

        # 检查文件大小
        file_size = os.path.getsize(pcap_path)
        logger.info(f"文件大小: {file_size / (1024*1024):.2f} MB")

        # 尝试读取PCAP文件
        try:
            packets = rdpcap(pcap_path)
            logger.info(f"成功读取 {len(packets)} 个数据包")
        except Exception as e:
            logger.error(f"读取PCAP文件失败: {str(e)}")
            return None

        # 创建DataConverter实例
        converter = DataConverter()

        # 处理PCAP文件
        logger.info(f"开始处理文件: {pcap_path}")
        flows = converter.process_pcap(pcap_path)

        if not flows:
            logger.error("没有提取到任何有效的流")
            return None

        # 创建输出目录
        output_dir = os.path.join(os.path.dirname(pcap_path), 'processed')
        os.makedirs(output_dir, exist_ok=True)

        # 保存处理后的数据
        output_file = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(pcap_path))[0]}.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(flows, f, ensure_ascii=False, indent=2)

        # 保存处理信息
        info = {
            'original_file': pcap_path,
            'processed_file': output_file,
            'process_time': datetime.now().isoformat(),
            'flow_count': len(flows),
            'total_packets': sum(len(flow['packet_length']) for flow in flows),
            'file_size': file_size
        }
        info_file = os.path.join(output_dir, 'info.json')
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, ensure_ascii=False, indent=2)

        logger.info(f"处理完成:")
        logger.info(f"- 提取的流数量: {len(flows)}")
        logger.info(f"- 总数据包数量: {sum(len(flow['packet_length']) for flow in flows)}")
        logger.info(f"- 输出文件: {output_file}")
        logger.info(f"- 信息文件: {info_file}")

        return info

    except Exception as e:
        logger.error(f"处理文件时出错: {str(e)}", exc_info=True)
        return None

if __name__ == '__main__':
    # 指定要处理的PCAP文件路径
    pcap_path = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\originaldata\data_20250403_222222\test.pcap"

    # 处理文件
    result = process_single_pcap(pcap_path)

    if result:
        print("\n处理成功！")
        print(f"提取了 {result['flow_count']} 个流")
        print(f"总数据包数量: {result['total_packets']}")
    else:
        print("\n处理失败！请查看日志文件了解详细信息。")
