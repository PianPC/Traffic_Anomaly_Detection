from scapy.all import *
import time
import threading
import queue

class PcapReplayer:
    def __init__(self, pcap_file, speed_factor=1.0):
        self.pcap_file = pcap_file
        self.speed_factor = speed_factor
        self.packets = rdpcap(pcap_file)
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()

    def start_replay(self):
        """开始重放PCAP文件"""
        # 计算第一个包的时间戳
        first_packet_time = self.packets[0].time

        # 创建发送线程
        sender_thread = threading.Thread(target=self._send_packets)
        sender_thread.daemon = True
        sender_thread.start()

        # 开始重放
        for packet in self.packets:
            if self.stop_event.is_set():
                break

            # 计算相对时间
            relative_time = packet.time - first_packet_time
            # 根据速度因子调整时间
            adjusted_time = relative_time / self.speed_factor

            # 将包和时间放入队列
            self.packet_queue.put((packet, adjusted_time))

        # 等待所有包发送完成
        self.packet_queue.join()

    def _send_packets(self):
        """发送数据包的线程函数"""
        while not self.stop_event.is_set():
            try:
                packet, send_time = self.packet_queue.get(timeout=1)
                # 等待到发送时间
                time.sleep(send_time)
                # 发送数据包
                sendp(packet, verbose=False)
                self.packet_queue.task_done()
            except queue.Empty:
                continue

    def stop_replay(self):
        """停止重放"""
        self.stop_event.set()

def replay_pcap(pcap_file, speed_factor=1.0):
    """重放PCAP文件的便捷函数"""
    replayer = PcapReplayer(pcap_file, speed_factor)
    replayer.start_replay()
    return replayer

if __name__ == "__main__":
    # 示例用法
    pcap_file = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\originaldata\Friday\Friday\split_output_00107_20170708024545.pcap"
    replayer = replay_pcap(pcap_file, speed_factor=1.0)  # 正常速度重放
