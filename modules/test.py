from flask import Flask, render_template, request, jsonify, send_file, Response, stream_with_context
import logging
import os
import json
from datetime import datetime
import subprocess
import threading
import queue
import time
import psutil
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np
from scapy.all import sniff, wrpcap
import sys
from scapy.all import rdpcap, TCP, UDP, IP
from decimal import Decimal
import multiprocessing as mp
from multiprocessing import Manager, Value, Array
from functools import partial
from collections import defaultdict
from models.dl.fsnet.fsnet_main_model import model as FSNetModel
import tensorflow as tf
from modules.pcap_to_json import process_dataset as process_single_dataset


def load_data(file_path):
    """加载并处理测试数据"""
    with open(file_path, 'r') as f:
        data = json.load(f)

    flow_data = []
    for item in data:
        packet_length = item['packet_length']
        arrive_time_delta = item['arrive_time_delta']
        flow_data.append([packet_length, arrive_time_delta])

    return flow_data

def predict_flow(model_service, flow_data):
    """使用FS-Net模型进行流量预测"""
    try:
        prediction = model_service.logit_online(flow_data)
        pred_label = int(np.argmax(prediction))
        confidence = float(np.max(prediction[0]))
        return pred_label, confidence
    except Exception as e:
        print(f"预测失败: {str(e)}")
        return None, None

def process_flow(file_path, model_service):
    """读取流数据并进行预测"""
    flow_data = load_data(file_path)
    for flow in flow_data:
        packet_length = flow[0]
        arrive_time_delta = flow[1]
        flow_input = [packet_length]  # 可以根据需要修改数据格式

        label, confidence = predict_flow(model_service, flow_input)
        if label is not None:
            print(f"预测标签: {label}, 置信度: {confidence}")

# 可以创建一个测试函数，模拟攻击流量
def test_attack_detection():
    # 模拟DDoS攻击流量 (大量短包)
    ddos_flow = [[60]*100]  # 100个60字节的包
    # 模拟PortScan流量 (大量短连接)
    portscan_flow = [[60, 60, 60, 60]]*20

    # 使用模型预测
    ddos_pred = model_service.logit_online(ddos_flow)
    portscan_pred = model_service.logit_online(portscan_flow)

    print(f"DDoS预测结果: {np.argmax(ddos_pred)}, 置信度: {np.max(ddos_pred)}")
    print(f"PortScan预测结果: {np.argmax(portscan_pred)}, 置信度: {np.max(portscan_pred)}")

model_service = FSNetModel('train_data_test4', randseed=128, splitrate=0.6, max_len=200)
# 假设模型已加载并准备好
test_attack_detection()
