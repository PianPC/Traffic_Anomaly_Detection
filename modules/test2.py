from scapy.all import rdpcap, TCP, UDP, IP
import time
from collections import defaultdict
from models.dl.fsnet.fsnet_main_model import model as FSNetModel
from scapy.all import sniff


flow_buffer = defaultdict(dict)  # 存储每个流的包

def process_packet(packet):
    """处理单个数据包"""
    if not IP in packet:
        return

    # 获取流标识
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = 'TCP'
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = 'UDP'
    else:
        return

    # 创建流标识符
    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

    # 获取包长
    packet_length = len(packet)
    # 确定包方向
    if src_ip < dst_ip:
        packet_length = packet_length
    else:
        packet_length = -packet_length

    # 更新流缓冲区
    current_time = time.time()
    if flow_id not in flow_buffer:
        flow_buffer[flow_id] = {
            'packets': [],
            'start_time': current_time,
            'last_update': current_time
        }

    flow_buffer[flow_id]['packets'].append(packet_length)
    flow_buffer[flow_id]['last_update'] = current_time

    # # 检查流是否满足预测条件
    # if len(flow_buffer[flow_id]['packets']) >= min_packets:
    #     try:
    #         # 提取特征并转换为模型输入格式
    #         flow_data = flow_buffer[flow_id]['packets']
    #         # 进行预测
    #         prediction = model_service.logit_online(flow_data)
    #         pred_label = int(np.argmax(prediction))
    #         # 将预测结果放入队列
    #         prediction_queue.put({
    #             'flow_id': flow_id,
    #             'prediction': pred_label,
    #             'timestamp': current_time,
    #             'packet_count': len(flow_buffer[flow_id]['packets']),
    #             'src_ip': src_ip,
    #             'dst_ip': dst_ip,
    #             'src_port': src_port,
    #             'dst_port': dst_port,
    #             'protocol': protocol
    #         })
    #         # 清空该流
    #         del flow_buffer[flow_id]
    #     except Exception as e:
    #         app.logger.error(f"预测失败: {str(e)}")
    #         # 如果预测失败，也清空该流
    #         del flow_buffer[flow_id]

    # # 清理超时的流
    # for fid in list(flow_buffer.keys()):
    #     if current_time - flow_buffer[fid]['last_update'] > flow_timeout:
    #         del flow_buffer[fid]

def packet_handler(packet):
    process_packet(packet)

min_packets = 10
model_service = FSNetModel('train_data_test', randseed=128, splitrate=0.6, max_len=200)
sniff(iface=interface, prn=packet_handler, store=0)
