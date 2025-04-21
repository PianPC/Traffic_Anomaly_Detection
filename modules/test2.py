
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

# 设置应用配置参数
print(os.path.join(BASE_DIR, 'originaldata'))  # 原始数据存储目录

