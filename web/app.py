#
from flask import Flask, render_template, request, jsonify, send_file, Response
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
from data_processor import DataConverter
from scapy.all import rdpcap, TCP, UDP, IP
from decimal import Decimal
import multiprocessing as mp
from functools import partial
import ctypes
from multiprocessing import Manager
from multiprocessing import Value, Array

app = Flask(
    __name__,                   # 告诉 Flask 当前模块（文件）的名称，用于定位项目的根目录
    static_folder='static',     # 指定静态文件在文件系统中的存储目录
    static_url_path='/static')  # 定义静态文件在 URL 中的访问路径前缀。修改此处可以达到隐藏静态路径的效果

# 获取基础路径
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# 设置应用配置参数
app.config['ORIGINAL_DATA_FOLDER'] = os.path.join(BASE_DIR, 'originaldata')  # 原始数据存储目录
app.config['DATASET_FOLDER'] = os.path.join(BASE_DIR, 'dataset')            # 处理后的数据集目录
app.config['MODEL_FOLDER'] = os.path.join(BASE_DIR, 'trained_models')        # 训练好的模型目录
app.config['MAX_CONTENT_LENGTH'] = None  # 移除文件大小限制
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')              # 文件上传目录

# 创建必要的文件目录
for path in [
    app.config['ORIGINAL_DATA_FOLDER'],
    app.config['DATASET_FOLDER'],
    app.config['MODEL_FOLDER'],
    app.config['UPLOAD_FOLDER']
]:
    os.makedirs(path, exist_ok=True)  # exist_ok=True表示如果目录已存在不报错

app.logger.setLevel(logging.INFO)   # 开发环境，使用 DEBUG 级别，记录所有细节。生产环境，使用 INFO 或更高，仅记录关键信息。

# 全局变量
realtime_data_queue = queue.Queue()  # 实时数据队列（用于线程间通信）
is_monitoring = False                # 监控状态标志
current_model = None                 # 当前使用的模型
current_interface = None             # 当前监控的网络接口
model_predictor = None               # 模型预测器实例
current_monitoring_session = None    # 当前监控会话

# 监控数据存储结构
monitoring_data = {
    'sessions': {},         # 存储所有监控会话
    'current_session': None # 当前活动会话
}

# 训练状态跟踪
training_status = {
    'is_training': False,  # 是否正在训练
    'progress': 0,         # 训练进度百分比
    'metrics': {           # 训练指标存储
        'epochs': [],      # 训练轮次
        'losses': [],      # 训练损失
        'accuracies': [],   # 训练准确率
        'val_losses': [],   # 验证损失
        'val_accuracies': [] # 验证准确率
    }
}

# 创建一个全局变量用于存储manager
manager = None
process_progress = None

# 全局变量用于跟踪处理状态
processing_status = {
    'is_processing': False,
    'current_file': '',
    'total_files': 0,
    'processed_files': 0
}

def init_process_manager():
    global manager, process_progress
    if manager is None:
        manager = Manager()
        process_progress = manager.dict({
            'current_file': '',
            'total_rows': 0,
            'processed_rows': 0
        })

@app.route('/')
def index():
    # 获取系统状态
    system_status = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }
    # 渲染index.html模板并传递系统状态数据
    # render_template 是 Flask 框架中用于渲染 HTML 模板的核心函数，它的作用是将动态数据与静态 HTML 模板结合，生成最终的网页内容返回给浏览器。
    return render_template('index.html', system_status=system_status)

@app.route('/get_system_status')
def get_system_status():
    """获取系统状态"""
    try:
        # 使用interval=1获取更精确的CPU使用率
        cpu_percent = psutil.cpu_percent(interval=1)
        status = {
            'cpu_usage': cpu_percent,
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_interfaces': psutil.net_if_stats(),
            'running_processes': len(psutil.pids()),
            'monitoring_sessions': len(monitoring_data['sessions'])
        }
        return jsonify({'status': 'success', 'data': status})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 任何访问该URL的请求（无论GET/POST）都会触发 realtime_monitor() 函数。
@app.route('/realtime_monitor', methods=['GET', 'POST'])
def realtime_monitor():
    # 获取系统状态
    # 如果仅是由<a href="{{ url_for('realtime_monitor') }}">点击链接会发送 ​​GET 请求​​ 到 /realtime_monitor，就只更新系统状态
    system_status = {
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    if request.method == 'POST':
        data = request.json
        action = data.get('action')
        if action == 'start':
            model_name = data.get('model')
            interfaces = data.get('interfaces', [])
            capture_duration = data.get('capture_duration', 60)  # 默认1分钟

            # 创建新的监控会话
            session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            current_monitoring_session = session_id
            monitoring_data['sessions'][session_id] = {
                'start_time': datetime.now(),
                'interfaces': interfaces,
                'model': model_name,
                'datasets': [], # 初始化空列表，用于存储捕获的数据集路径，['dataset_1.pcap', 'dataset_2.pcap']
                'capture_duration': capture_duration
            }

            # 初始化模型
            model_path = os.path.join(app.config['MODEL_FOLDER'], model_name)
            if os.path.exists(model_path):
                model_module = __import__(f'models.{model_name.split("_")[0]}.model', fromlist=['ModelPredictor'])
                model_predictor = model_module.ModelPredictor(model_path)
                is_monitoring = True

                # 启动监控线程
                threading.Thread(
                    target=monitor_traffic,
                    args=(session_id, capture_duration),
                    daemon=True
                ).start()

                return jsonify({'status': 'success', 'message': '监控已启动'})
            else:
                return jsonify({'status': 'error', 'message': '模型不存在'})
        elif action == 'stop':
            is_monitoring = False
            model_predictor = None
            current_monitoring_session = None
            return jsonify({'status': 'success', 'message': '监控已停止'})
    return render_template('realtime_monitor.html', system_status=system_status)

@app.route('/get_interfaces')
def get_interfaces():
    """获取可用的网络接口列表"""
    try:
        interfaces = []
        for interface, stats in psutil.net_if_stats().items():
            # 过滤掉回环接口和虚拟接口
            if interface != 'lo' and not interface.startswith('veth'):
                interfaces.append({
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed if stats.speed > 0 else 'Unknown',
                    'mtu': stats.mtu
                })
        return jsonify({
            'status': 'success',
            'interfaces': interfaces
        })
    except Exception as e:
        app.logger.error(f"获取网络接口失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/get_monitor_data')
def get_monitor_data():
    if not is_monitoring:
        return jsonify({'status': 'error', 'message': '监控未启动'})

    try:
        data = realtime_data_queue.get_nowait()
        return jsonify({
            'status': 'success',
            'data': data
        })
    except queue.Empty:
        return jsonify({
            'status': 'success',
            'data': {
                'traffic': [],
                'anomaly': [
                    {'value': 0, 'name': '正常'},
                    {'value': 0, 'name': '异常'}
                ]
            }
        })

@app.route('/get_datasets')
def get_datasets():
    """获取可用的数据集列表（文件夹）"""
    try:
        train_datasets = []
        train_dataset_dir = os.path.join(app.config['DATASET_FOLDER'], 'train_data')
        if os.path.exists(train_dataset_dir):
            for item in os.listdir(train_dataset_dir):
                item_path = os.path.join(train_dataset_dir, item)
                if os.path.isdir(item_path):
                    # 检查目录中是否包含json文件
                    json_files = [f for f in os.listdir(item_path) if f.endswith('.json')]
                    if json_files:
                        train_datasets.append({
                            'name': item,
                            'path': item_path,
                            'file_count': len(json_files)
                        })
        return jsonify({'status': 'success', 'train_datasets': train_datasets})
    except Exception as e:
        app.logger.error(f"获取数据集列表错误: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/historical_analysis', methods=['GET', 'POST'])
def historical_analysis():
    # 获取系统状态（保持不变）
    system_status = {
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': '没有文件被上传'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': '没有选择文件'})

        if file:
            try:
                # 检查文件大小（保持不变）
                file.seek(0, 2)
                file_size = file.tell()
                file.seek(0)

                if app.config['MAX_CONTENT_LENGTH'] and file_size > app.config['MAX_CONTENT_LENGTH']:
                    return jsonify({'status': 'error', 'message': '文件大小超过限制'})

                # 创建目录结构
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                dataset_name = f"data_{timestamp}"
                original_dir = os.path.join(app.config['ORIGINAL_DATA_FOLDER'], 'historical_analysis', dataset_name)
                dataset_dir = os.path.join(app.config['DATASET_FOLDER'], 'historical_analysis',dataset_name)
                os.makedirs(original_dir, exist_ok=True)
                os.makedirs(dataset_dir, exist_ok=True)

                # 保存原始文件
                filename = secure_filename(file.filename)
                original_path = os.path.join(original_dir, filename)
                file.save(original_path)

                # 根据文件类型选择处理器
                if filename.lower().endswith('.csv'):
                    result = process_csv_file(original_path, dataset_dir)
                elif filename.lower().endswith(('.pcap', '.pcapng')):
                    result = process_pcap_file(original_path, dataset_dir)
                else:
                    return jsonify({
                        'status': 'error',
                        'message': '不支持的文件类型',
                        'supported_types': ['csv', 'pcap', 'pcapng']
                    })

                if result['status'] == 'error':
                    return jsonify(result)

                return jsonify({
                    'status': 'success',
                    'message': '文件上传和处理完成',
                    'dataset_name': dataset_name,
                    'file_type': 'PCAP' if filename.lower().endswith(('.pcap', '.pcapng')) else 'CSV'
                })

            except Exception as e:
                app.logger.error(f"文件处理错误: {str(e)}", exc_info=True)
                return jsonify({'status': 'error', 'message': str(e)})

    return render_template('historical_analysis.html', system_status=system_status)

@app.route('/process_progress')
def get_process_progress():
    """获取处理进度"""
    init_process_manager()  # 确保manager已初始化
    def generate():
        while True:
            if process_progress['total_rows'] > 0:
                progress = int((process_progress['processed_rows'] / process_progress['total_rows']) * 100)
                yield f"data: {json.dumps({'status': 'progress', 'progress': progress})}\n\n"
            time.sleep(0.5)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/check_processing_status')
def check_processing_status():
    """检查处理状态"""
    if processing_status['is_processing']:
        return jsonify({'status': 'processing'})
    else:
        return jsonify({'status': 'completed'})

def process_csv_chunk(chunk, output_dir):
    """处理CSV数据块"""
    try:
        results = {}
        for _, row in chunk.iterrows():
            # 提取包长序列
            packet_length = []
            # 前向包
            if row['Total Fwd Packets'] > 0:
                avg_fwd_length = row['Total Length of Fwd Packets'] / row['Total Fwd Packets']
                packet_length.extend([avg_fwd_length] * int(row['Total Fwd Packets']))
            # 反向包
            if row['Total Backward Packets'] > 0:
                avg_bwd_length = row['Total Length of Bwd Packets'] / row['Total Backward Packets']
                packet_length.extend([-avg_bwd_length] * int(row['Total Backward Packets']))

            # 提取到达时间间隔
            arrive_time_delta = [0]
            total_packets = int(row['Total Fwd Packets'] + row['Total Backward Packets'])

            if total_packets > 1:
                if row['Total Fwd Packets'] > 1:
                    fwd_iat = row['Fwd IAT Total'] / (row['Total Fwd Packets'] - 1)
                    for i in range(1, int(row['Total Fwd Packets'])):
                        arrive_time_delta.append(arrive_time_delta[-1] + fwd_iat)

                if row['Total Backward Packets'] > 0:
                    bwd_iat = row['Bwd IAT Total'] / row['Total Backward Packets']
                    for i in range(int(row['Total Backward Packets'])):
                        arrive_time_delta.append(arrive_time_delta[-1] + bwd_iat)

            if packet_length:
                label = row['Label']
                if label not in results:
                    results[label] = []
                results[label].append({
                    'packet_length': packet_length,
                    'arrive_time_delta': arrive_time_delta
                })

        return results
    except Exception as e:
        app.logger.error(f"处理数据块时出错: {str(e)}")
        return {}

def process_csv_file(file_path, output_dir):
    """处理CSV文件，按Label分类保存为JSON格式"""
    try:
        # 更新处理状态
        processing_status['is_processing'] = True
        processing_status['current_file'] = os.path.basename(file_path)
        processing_status['total_files'] = 1
        processing_status['processed_files'] = 0

        # 读取CSV文件，尝试不同的编码
        encodings = ['utf-8', 'gbk', 'gb2312', 'gb18030']
        df = None
        for encoding in encodings:
            try:
                df = pd.read_csv(file_path, encoding=encoding, skipinitialspace=True)
                break
            except UnicodeDecodeError:
                continue

        if df is None:
            processing_status['is_processing'] = False
            return {'status': 'error', 'message': '无法读取CSV文件，请检查文件编码'}

        # 检查必要列
        required_columns = {
            'Label',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Total Length of Fwd Packets',
            'Total Length of Bwd Packets',
            'Flow Duration',
            'Flow IAT Mean',
            'Fwd IAT Mean',
            'Bwd IAT Mean',
            'Fwd IAT Total',
            'Bwd IAT Total'
        }

        # 检查列名（不区分大小写和前后空格）
        existing_columns = {col.strip().lower(): col for col in df.columns}
        missing_cols = []
        for req_col in required_columns:
            if req_col.strip().lower() not in existing_columns:
                missing_cols.append(req_col)

        if missing_cols:
            processing_status['is_processing'] = False
            app.logger.error(f"CSV文件缺少必要列: {missing_cols}，实际列名: {df.columns.tolist()}")
            return {'status': 'error', 'message': f'缺少必要列: {missing_cols}'}

        # 创建标准化列名映射（保留原始列名）
        col_mapping = {
            existing_columns[req_col.strip().lower()]: req_col
            for req_col in required_columns
        }
        df = df.rename(columns=col_mapping)

        # 将数据分成多个块进行并行处理
        num_processes = mp.cpu_count()
        chunk_size = len(df) // num_processes + 1
        chunks = [df.iloc[i:i+chunk_size] for i in range(0, len(df), chunk_size)]

        # 创建进程池
        with mp.Pool(processes=num_processes) as pool:
            # 使用partial固定output_dir参数
            process_func = partial(process_csv_chunk, output_dir=output_dir)
            # 并行处理数据块
            results = pool.map(process_func, chunks)

        # 合并结果
        merged_results = {}
        for result in results:
            for label, samples in result.items():
                if label not in merged_results:
                    merged_results[label] = []
                merged_results[label].extend(samples)

        # 保存结果
        for label, samples in merged_results.items():
            safe_label = label.replace('/', '_').replace('\\', '_')
            output_file = os.path.join(output_dir, f"{safe_label}.json")

            # 检查文件是否已存在，如果存在则追加
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_samples = json.load(f)
                samples = existing_samples + samples

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(samples, f, ensure_ascii=False, indent=2)
            app.logger.info(f"已保存{len(samples)}个样本到{output_file}")

        # 更新处理状态为完成
        processing_status['is_processing'] = False
        processing_status['processed_files'] = 1
        return {'status': 'success', 'message': '文件处理完成'}

    except Exception as e:
        # 发生错误时更新状态
        processing_status['is_processing'] = False
        app.logger.error(f"处理CSV文件时出错: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def process_pcap_chunk(packets, output_dir):
    """处理PCAP数据块"""
    try:
        flows = {}
        for pkt in packets:
            if not (IP in pkt and (TCP in pkt or UDP in pkt)):
                continue

            # 提取五元组作为流标识
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            protocol = 'TCP' if TCP in pkt else 'UDP'

            # 创建流标识键（双向流合并）
            forward_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            backward_key = (dst_ip, dst_port, src_ip, src_port, protocol)

            # 确定流方向
            if forward_key in flows:
                flow_key = forward_key
                direction = 1  # 正向
            elif backward_key in flows:
                flow_key = backward_key
                direction = -1  # 反向
            else:
                flow_key = forward_key
                direction = 1  # 新流默认正向
                flows[flow_key] = {'packets': [], 'timestamps': []}

            # 记录包信息和时间戳
            flows[flow_key]['packets'].append({
                'length': len(pkt) * direction,
                'time': float(pkt.time)
            })

        return flows
    except Exception as e:
        app.logger.error(f"处理PCAP数据块时出错: {str(e)}")
        return {}

def process_pcap_file(file_path, output_dir):
    """处理PCAP文件，按流分类保存为JSON格式"""
    try:
        # 更新处理状态
        processing_status['is_processing'] = True
        processing_status['current_file'] = os.path.basename(file_path)
        processing_status['total_files'] = 1
        processing_status['processed_files'] = 0

        # 读取PCAP文件
        packets = rdpcap(file_path)
        if len(packets) == 0:
            processing_status['is_processing'] = False
            return {'status': 'error', 'message': 'PCAP文件为空'}

        # 将数据包分成多个块进行并行处理
        num_processes = mp.cpu_count()
        chunk_size = len(packets) // num_processes + 1
        chunks = [packets[i:i+chunk_size] for i in range(0, len(packets), chunk_size)]

        # 创建进程池
        with mp.Pool(processes=num_processes) as pool:
            # 使用partial固定output_dir参数
            process_func = partial(process_pcap_chunk, output_dir=output_dir)
            # 并行处理数据块
            results = pool.map(process_func, chunks)

        # 合并结果
        merged_flows = {}
        for result in results:
            for flow_key, flow_data in result.items():
                if flow_key not in merged_flows:
                    merged_flows[flow_key] = flow_data
                else:
                    merged_flows[flow_key]['packets'].extend(flow_data['packets'])
                    merged_flows[flow_key]['timestamps'].extend(flow_data['timestamps'])

        # 转换为目标格式并保存
        results = []
        for flow_key, flow_data in merged_flows.items():
            if len(flow_data['packets']) < 2:  # 忽略单包流
                continue

            # 按时间排序包
            sorted_packets = sorted(flow_data['packets'], key=lambda x: x['time'])

            # 提取包长序列
            packet_length = [pkt['length'] for pkt in sorted_packets]

            # 计算到达时间间隔
            timestamps = [pkt['time'] for pkt in sorted_packets]
            arrive_time_delta = [0]  # 第一个包为0
            for i in range(1, len(timestamps)):
                delta = timestamps[i] - timestamps[i-1]
                arrive_time_delta.append(max(delta, 1e-6))  # 避免0间隔

            results.append({
                'packet_length': packet_length,
                'arrive_time_delta': arrive_time_delta
            })

        # 保存为JSON
        if results:
            filename = os.path.basename(file_path).rsplit('.', 1)[0] + '.json'
            output_file = os.path.join(output_dir, filename)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            app.logger.info(f"已保存{len(results)}条流到{output_file}")

            # 更新处理状态为完成
            processing_status['is_processing'] = False
            processing_status['processed_files'] = 1
            return {'status': 'success', 'message': 'PCAP处理完成'}
        else:
            processing_status['is_processing'] = False
            return {'status': 'error', 'message': '未提取到有效网络流'}

    except Exception as e:
        # 发生错误时更新状态
        processing_status['is_processing'] = False
        app.logger.error(f"处理PCAP文件时出错: {str(e)}")
        return {'status': 'error', 'message': str(e)}

@app.route('/analyze_data', methods=['POST'])
def analyze_data():
    data = request.json
    model_name = data.get('model')
    filename = data.get('filename')

    try:
        file_path = os.path.join(app.config['DATASET_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': '文件不存在'
            })

        # 初始化模型
        model_path = os.path.join(app.config['MODEL_FOLDER'], model_name)
        if not os.path.exists(model_path):
            return jsonify({
                'status': 'error',
                'message': '模型不存在'
            })

        model_module = __import__(f'models.{model_name.split("_")[0]}.model', fromlist=['ModelPredictor'])
        model_predictor = model_module.ModelPredictor(model_path)

        # 加载数据
        data_processor = DataProcessor()
        flows = data_processor.load_from_json(file_path)

        # 分析数据
        results = []
        for flow in flows:
            prediction = model_predictor.predict(flow)
            results.append(prediction)

        # 计算统计信息
        total_flows = len(results)
        normal_flows = sum(1 for r in results if r == 0)
        anomaly_flows = sum(1 for r in results if r == 1)

        if total_flows > 0:
            normal_percent = (normal_flows / total_flows) * 100
            anomaly_percent = (anomaly_flows / total_flows) * 100
        else:
            normal_percent = 100
            anomaly_percent = 0

        # 准备返回数据
        analysis_result = {
            'traffic_distribution': [
                {'value': normal_percent, 'name': '正常流量'},
                {'value': anomaly_percent, 'name': '异常流量'}
            ],
            'anomaly_types': {
                'DDoS攻击': anomaly_flows,
                '端口扫描': 0,
                '其他异常': 0
            },
            'file_size': f"{os.path.getsize(file_path) / (1024*1024):.2f}MB",
            'total_flows': total_flows,
            'anomaly_flows': anomaly_flows,
            'accuracy': 95.5,  # 这里可以添加实际的准确率计算
            'detailed_analysis': f"检测到{anomaly_flows}个异常流量，包括{anomaly_flows}个DDoS攻击。"
        }

        return jsonify({
            'status': 'success',
            'data': analysis_result
        })
    except Exception as e:
        app.logger.error(f"分析错误: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/model_training', methods=['GET', 'POST'])
def model_training():
    # 获取系统状态
    system_status = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    if request.method == 'POST':
        data = request.json
        action = data.get('action')

        if action == 'start':
            model = data.get('model')
            dataset = data.get('dataset')

            if not all([model, dataset]):
                return jsonify({'status': 'error', 'message': '参数不完整'})

            training_status['is_training'] = True
            training_status['progress'] = 0
            training_status['metrics'] = {
                'epochs': [],
                'losses': [],
                'accuracies': [],
                'val_losses': [],
                'val_accuracies': []
            }

            # 启动训练线程
            threading.Thread(
                target=train_model,
                args=(model, dataset),
                daemon=True
            ).start()

            return jsonify({'status': 'success', 'message': '训练已启动'})

        elif action == 'stop':
            training_status['is_training'] = False
            return jsonify({'status': 'success', 'message': '训练已停止'})

    return render_template('model_training.html', system_status=system_status)

@app.route('/get_training_status')
def get_training_status():
    return jsonify({
        'status': 'success',
        'is_completed': not training_status['is_training'],
        'progress': training_status['progress'],
        'metrics': training_status['metrics'],
        'status_message': '正在训练...' if training_status['is_training'] else '训练已完成'
    })

@app.route('/get_models')
def get_models():
    """获取所有已训练好的模型"""
    try:
        models = []
        model_dir = app.config['MODEL_FOLDER']
        if os.path.exists(model_dir):
            for model_name in os.listdir(model_dir):
                model_path = os.path.join(model_dir, model_name)
                if os.path.isdir(model_path):
                    # 检查是否存在模型文件
                    model_files = [f for f in os.listdir(model_path) if f.endswith('.h5') or f.endswith('.pth')]
                    if model_files:
                        models.append({
                            'name': model_name,
                            'path': model_path,
                            'file_count': len(model_files)
                        })
        return jsonify({'status': 'success', 'models': models})
    except Exception as e:
        app.logger.error(f"获取模型列表错误: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_available_models')
def get_available_models():
    """获取可用的模型列表"""
    try:
        models = []
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')

        # 遍历models目录下的子目录
        for model_type in os.listdir(models_dir):
            type_dir = os.path.join(models_dir, model_type)
            if os.path.isdir(type_dir):
                # 遍历每个类型目录下的模型目录
                for model_name in os.listdir(type_dir):
                    model_dir = os.path.join(type_dir, model_name)
                    if os.path.isdir(model_dir):
                        # 检查是否存在主模型文件
                        main_model_file = os.path.join(model_dir, f"{model_name}_main_model.py")
                        if os.path.exists(main_model_file):
                            models.append({
                                'name': model_name,
                                'type': model_type
                            })

        return jsonify({
            'status': 'success',
            'models': models
        })
    except Exception as e:
        app.logger.error(f"获取可用模型列表时出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/train_model', methods=['POST'])
def train_model():
    """开始训练模型"""
    try:
        data = request.json
        model_name = data.get('model')
        dataset_name = data.get('dataset')

        if not model_name or not dataset_name:
            return jsonify({
                'status': 'error',
                'message': '缺少必要参数'
            })

        # 构建训练命令
        model_type = None
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')

        # 查找模型类型
        for type_dir in os.listdir(models_dir):
            type_path = os.path.join(models_dir, type_dir)
            if os.path.isdir(type_path) and model_name in os.listdir(type_path):
                model_type = type_dir
                break

        if not model_type:
            return jsonify({
                'status': 'error',
                'message': f'未找到模型 {model_name}'
            })

        # 构建训练命令
        model_dir = os.path.join(models_dir, model_type, model_name)
        main_model_file = os.path.join(model_dir, f"{model_name}_main_model.py")
        dataset_path = os.path.join(app.config['DATASET_FOLDER'], 'train_data', dataset_name)

        if not os.path.exists(main_model_file):
            return jsonify({
                'status': 'error',
                'message': f'未找到模型主文件 {main_model_file}'
            })

        if not os.path.exists(dataset_path):
            return jsonify({
                'status': 'error',
                'message': f'未找到数据集 {dataset_path}'
            })

        # 启动训练进程
        cmd = ['python', main_model_file, '--dataset', dataset_path]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 存储进程信息
        training_processes[process.pid] = {
            'process': process,
            'model': model_name,
            'dataset': dataset_name,
            'start_time': datetime.now().isoformat()
        }

        return jsonify({
            'status': 'success',
            'message': '训练已启动',
            'pid': process.pid
        })

    except Exception as e:
        app.logger.error(f"启动训练时出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/upload_training_dataset', methods=['POST'])
def upload_training_dataset():
    """处理训练数据集上传"""
    try:
        # 1. 基础验证
        if 'files[]' not in request.files:
            return jsonify({'status': 'error', 'message': '没有文件被上传'})

        dataset_name = request.form.get('datasetName', '').strip()
        if not dataset_name:
            return jsonify({'status': 'error', 'message': '未提供数据集名称'})

        # 2. 创建目录
        originaldata_dir = os.path.join(app.config['ORIGINAL_DATA_FOLDER'], 'train_data', dataset_name)
        os.makedirs(originaldata_dir, exist_ok=True)
        dataset_dir = os.path.join(app.config['DATASET_FOLDER'], 'train_data', dataset_name)
        os.makedirs(dataset_dir, exist_ok=True)

        # 3. 处理文件上传
        processed_files = []
        for file in request.files.getlist('files[]'):
            if not file.filename:
                continue

            filename = secure_filename(file.filename)
            if not filename:  # 安全过滤
                continue

            file_path = os.path.join(originaldata_dir, filename)
            file.save(file_path)
            processed_files.append(filename)

            # 4. 自动处理CSV文件
            if filename.endswith('.csv'):
                result = process_csv_file(file_path, dataset_dir)
                if result.get('status') == 'error':
                    return jsonify(result)

        return jsonify({
            'status': 'success',
            'message': '文件上传和处理完成',
            'dataset_name': dataset_name,
            'processed_files': processed_files
        })

    except Exception as e:
        app.logger.error(f"上传失败: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'上传失败: {str(e)}'
        })

def monitor_traffic(session_id, capture_duration):
    global is_monitoring
    session_data = monitoring_data['sessions'][session_id]
    dataset_count = 1

    while is_monitoring:
        try:
            # 创建数据集目录
            dataset_name = f"dataset_{dataset_count}"
            original_data_dir = os.path.join(app.config['ORIGINAL_DATA_FOLDER'], session_id)
            processed_data_dir = os.path.join(app.config['DATASET_FOLDER'], session_id)
            os.makedirs(original_data_dir, exist_ok=True)
            os.makedirs(processed_data_dir, exist_ok=True)

            # 捕获流量
            packets = []
            start_time = time.time()

            def packet_callback(packet):
                if not is_monitoring:
                    return False
                packets.append(packet)

            # 为每个网卡创建监听线程
            sniff_threads = []
            for interface in session_data['interfaces']:
                thread = threading.Thread(
                    target=sniff,
                    args=(interface,),
                    kwargs={'prn': packet_callback, 'store': 0},
                    daemon=True
                )
                thread.start()
                sniff_threads.append(thread)

            # 等待指定时间或直到停止信号
            while is_monitoring:
                if capture_duration > 0 and time.time() - start_time >= capture_duration:
                    break
                time.sleep(1)

            # 停止所有抓包线程
            is_monitoring = False
            time.sleep(1)  # 等待抓包线程结束
            is_monitoring = True

            # 保存原始数据
            pcap_file = os.path.join(original_data_dir, f"{dataset_name}.pcap")
            wrpcap(pcap_file, packets)

            # 处理数据
            data_processor = DataProcessor()
            flows = data_processor.process_pcap(pcap_file)

            # 保存处理后的数据
            json_file = os.path.join(processed_data_dir, f"{dataset_name}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(flows, f, ensure_ascii=False, indent=2)

            # 更新会话信息
            session_data['datasets'].append({
                'name': dataset_name,
                'original_file': pcap_file,
                'processed_file': json_file,
                'timestamp': datetime.now().isoformat(),
                'duration': time.time() - start_time,
                'packet_count': len(packets)
            })

            # 分析数据
            analyze_packets(packets, session_id, dataset_name)

            dataset_count += 1

        except Exception as e:
            app.logger.error(f"监控错误: {str(e)}")
            time.sleep(5)  # 发生错误时等待一段时间后重试

def analyze_packets(packets, session_id, dataset_name):
    try:
        if model_predictor is None:
            return

        # 使用模型进行预测
        predictions = model_predictor.predict_batch(packets)

        # 统计结果
        normal_count = sum(1 for p in predictions if p == 0)
        anomaly_count = sum(1 for p in predictions if p == 1)

        total = normal_count + anomaly_count
        if total > 0:
            normal_percent = (normal_count / total) * 100
            anomaly_percent = (anomaly_count / total) * 100
        else:
            normal_percent = 100
            anomaly_percent = 0

        # 更新实时数据
        analysis_result = {
            'session_id': session_id,
            'dataset_name': dataset_name,
            'timestamp': datetime.now().isoformat(),
            'traffic': [
                {'name': datetime.now().strftime('%H:%M:%S'), 'value': len(packets)}
            ],
            'anomaly': [
                {'value': normal_percent, 'name': '正常'},
                {'value': anomaly_percent, 'name': '异常'}
            ],
            'statistics': {
                'total_packets': total,
                'normal_packets': normal_count,
                'anomaly_packets': anomaly_count
            }
        }

        realtime_data_queue.put(analysis_result)

    except Exception as e:
        app.logger.error(f"分析错误: {str(e)}")

def train_model(model, dataset):
    """训练模型"""
    try:
        # 构建命令
        cmd = [
            './run.sh',
            'train',
            model,
            dataset
        ]

        # 执行训练命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 返回进程ID，前端可以通过这个ID查询训练状态
        return jsonify({
            'status': 'success',
            'pid': process.pid
        })

    except Exception as e:
        app.logger.error(f"训练模型时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # 初始化进程管理器
    init_process_manager()
    app.run(debug=True)
