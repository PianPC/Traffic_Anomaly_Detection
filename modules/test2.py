
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

# 获取基础路径
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

model_name = 'fsnet'
dataset_name = 'data_20250418_115435'

if not model_name or not dataset_name:
    print({'status': 'error', 'message': '缺少模型或数据集参数'})

# 构建数据集目录路径
dataset_dir = os.path.join(BASE_DIR, 'dataset', dataset_name)

if not os.path.exists(dataset_dir):
    print({
        'status': 'error',
        'message': f'数据集目录不存在: {dataset_dir}'
    })

# 查找目录下的JSON文件（修复点：确保json_path正确定义）
json_files = [
    f for f in os.listdir(dataset_dir)
    if f.endswith('.json') and os.path.isfile(os.path.join(dataset_dir, f))
]

if not json_files:
    print({
        'status': 'error',
        'message': f'数据集目录中没有找到JSON文件: {dataset_dir}'
    })

# 使用第一个找到的JSON文件（修复点：确保json_path赋值）
json_filename = json_files[0]
json_path = os.path.join(dataset_dir, json_filename)


print(json_path)
