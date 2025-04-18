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

model_service = FSNetModel('train_data_test4', randseed=128, splitrate=0.6, max_len=200)
# 假设模型已加载并准备好
process_flow("E:/workplace/Code/VSCodeProject/traffic_anomaly_detection/dataset/data_20250418_144742/test4.json", model_service)
