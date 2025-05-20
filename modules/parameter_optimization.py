import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import json
import os
import time
import threading
import queue
import tensorflow as tf
from models.dl.fsnet.fsnet_main_model import model as FSNetModel
from pcap_replay import replay_pcap
from score import calculate_accuracy
from scapy.all import rdpcap, TCP, UDP, IP

class ParameterOptimizer:
    def __init__(self, pcap_file, csv_file, output_dir):
        self.pcap_file = pcap_file
        self.csv_file = csv_file
        self.output_dir = output_dir
        self.results = []
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.model_service = None
        self.prediction_queue = queue.Queue()
        self.flow_buffer = {}

    def init_model(self):
        """初始化模型"""
        try:
            self.model_service = FSNetModel('train_data_test', randseed=128, splitrate=0.6, max_len=200)
            # 确保模型目录存在
            model_dir = os.path.join('data', 'fsnet_train_data_test_model', 'log')
            if not os.path.exists(model_dir):
                print(f"模型目录不存在: {model_dir}")
                return False
            # 检查是否有训练好的模型
            ckpt = tf.train.get_checkpoint_state(model_dir)
            if not ckpt or not ckpt.model_checkpoint_path:
                print("未找到训练好的模型")
                return False
            return True
        except Exception as e:
            print(f"加载模型失败: {str(e)}")
            return False

    def process_packet(self, packet, flow_timeout, min_packets):
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
        current_time = time.time()

        # 获取包长
        packet_length = len(packet)
        # 确定包方向
        if src_ip < dst_ip:
            packet_length = packet_length
        else:
            packet_length = -packet_length

        # 初始化流统计
        if flow_id not in self.flow_buffer:
            self.flow_buffer[flow_id] = {
                'packets': [],
                'first_packet_time': current_time,
                'last_update': current_time
            }

        self.flow_buffer[flow_id]['packets'].append(packet_length)
        self.flow_buffer[flow_id]['last_update'] = current_time

        # 检查流是否满足预测条件
        if len(self.flow_buffer[flow_id]['packets']) >= min_packets:
            try:
                # 确保flow_data是一个列表
                flow_data = [self.flow_buffer[flow_id]['packets']]
                if not isinstance(flow_data, list):
                    flow_data = [flow_data]

                # 进行预测
                prediction = self.model_service.logit_online(flow_data)
                pred_label = int(np.argmax(prediction))
                confidence = float(np.max(prediction[0]))

                # 将预测结果放入队列
                self.prediction_queue.put({
                    'flow_id': flow_id,
                    'prediction': pred_label,
                    'confidence': confidence,
                    'timestamp': current_time,
                    'packet_count': len(self.flow_buffer[flow_id]['packets']),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol
                })
                # 清空该流
                del self.flow_buffer[flow_id]
            except Exception as e:
                print(f"预测失败: {str(e)}")
                # 如果预测失败，也清空该流
                del self.flow_buffer[flow_id]

        # 清理超时的流
        for fid in list(self.flow_buffer.keys()):
            if current_time - self.flow_buffer[fid]['last_update'] > flow_timeout:
                del self.flow_buffer[fid]

    def test_parameters(self, flow_timeout_range, min_packets_range):
        """测试不同的参数组合"""
        if not self.init_model():
            print("模型初始化失败")
            return

        for flow_timeout in flow_timeout_range:
            for min_packets in min_packets_range:
                if self.stop_event.is_set():
                    break

                print(f"测试参数组合: flow_timeout={flow_timeout}, min_packets={min_packets}")

                # 清空之前的预测结果
                self.prediction_queue = queue.Queue()
                self.flow_buffer = {}

                # 创建临时配置文件
                config = {
                    'flow_timeout': flow_timeout,
                    'min_packets': min_packets
                }

                # 保存配置
                config_file = os.path.join(self.output_dir, f'config_{flow_timeout}_{min_packets}.json')
                with open(config_file, 'w') as f:
                    json.dump(config, f)

                # 重放PCAP文件并处理数据包
                def packet_handler(packet):
                    self.process_packet(packet, flow_timeout, min_packets)

                # 使用scapy的sniff函数捕获重放的包
                replayer = replay_pcap(self.pcap_file)
                sniff(iface=None, prn=packet_handler, store=0, stop_filter=lambda x: self.stop_event.is_set())

                # 等待所有预测完成
                time.sleep(2)  # 给一些时间让所有预测完成

                # 保存预测结果
                predictions = []
                while not self.prediction_queue.empty():
                    predictions.append(self.prediction_queue.get())

                prediction_file = os.path.join(self.output_dir, f'realtime_predictions_{flow_timeout}_{min_packets}.json')
                with open(prediction_file, 'w') as f:
                    json.dump(predictions, f)

                # 计算准确率
                accuracy, total, right = calculate_accuracy(prediction_file, self.csv_file)

                # 保存结果
                result = {
                    'flow_timeout': flow_timeout,
                    'min_packets': min_packets,
                    'accuracy': accuracy,
                    'total': total,
                    'right': right
                }
                self.results.append(result)
                self.result_queue.put(result)

                print(f"准确率: {accuracy:.2f}%, 总样本: {total}, 正确预测: {right}")

                # 清理临时文件
                os.remove(config_file)
                os.remove(prediction_file)

    def plot_results(self):
        """绘制结果图"""
        # 准备数据
        flow_timeouts = [r['flow_timeout'] for r in self.results]
        min_packets = [r['min_packets'] for r in self.results]
        accuracies = [r['accuracy'] for r in self.results]

        # 创建3D图
        fig = plt.figure(figsize=(10, 8))
        ax = fig.add_subplot(111, projection='3d')

        # 绘制散点图
        scatter = ax.scatter(flow_timeouts, min_packets, accuracies, c=accuracies, cmap='viridis')

        # 设置标签
        ax.set_xlabel('Flow Timeout (s)')
        ax.set_ylabel('Min Packets')
        ax.set_zlabel('Accuracy (%)')

        # 添加颜色条
        plt.colorbar(scatter, label='Accuracy (%)')

        # 保存图片
        plt.savefig(os.path.join(self.output_dir, 'parameter_optimization.png'))
        plt.close()

        # 保存结果到CSV
        with open(os.path.join(self.output_dir, 'optimization_results.csv'), 'w') as f:
            f.write('flow_timeout,min_packets,accuracy,total,right\n')
            for result in self.results:
                f.write(f"{result['flow_timeout']},{result['min_packets']},{result['accuracy']},{result['total']},{result['right']}\n")

    def stop(self):
        """停止优化过程"""
        self.stop_event.set()

def optimize_parameters(pcap_file, csv_file, output_dir,
                       flow_timeout_range=np.arange(0.1, 2.1, 0.1),
                       min_packets_range=range(5, 21)):
    """优化参数的便捷函数"""
    optimizer = ParameterOptimizer(pcap_file, csv_file, output_dir)

    # 创建优化线程
    optimization_thread = threading.Thread(
        target=optimizer.test_parameters,
        args=(flow_timeout_range, min_packets_range)
    )
    optimization_thread.daemon = True
    optimization_thread.start()

    return optimizer

if __name__ == "__main__":
    # 设置文件路径
    pcap_file = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\originaldata\Friday\Friday\split_output_00107_20170708024545.pcap"
    csv_file = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\output\Friday-WorkingHours-flow_id_label.csv"
    output_dir = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\output\optimization"

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    # 开始优化
    optimizer = optimize_parameters(
        pcap_file,
        csv_file,
        output_dir,
        flow_timeout_range=np.arange(0.5, 10.0, 0.5),  # 0.5到2.0秒，步长0.1
        min_packets_range=range(1, 20)  # 5到20个包
    )

    # 等待优化完成
    while not optimizer.stop_event.is_set():
        time.sleep(1)

    # 绘制结果
    optimizer.plot_results()
