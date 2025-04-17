#
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


app = Flask(
    __name__,                   # 告诉 Flask 当前模块（文件）的名称，用于定位项目的根目录
    static_folder='static',     # 指定静态文件在文件系统中的存储目录
    static_url_path='/static')  # 定义静态文件在 URL 中的访问路径前缀。修改此处可以达到隐藏静态路径的效果

# 获取基础路径
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# 设置应用配置参数
app.config['ORIGINAL_DATA_FOLDER'] = os.path.join(BASE_DIR, 'originaldata')  # 原始数据存储目录
app.config['DATASET_FOLDER'] = os.path.join(BASE_DIR, 'dataset')            # 处理后的数据集目录
app.config['OUTPUT_FOLDER'] = os.path.join(BASE_DIR, 'output')              # 文件上传目录
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = None  # 移除文件大小限制


# 创建必要的文件目录
for path in [
    app.config['ORIGINAL_DATA_FOLDER'],
    app.config['DATASET_FOLDER'],
    app.config['OUTPUT_FOLDER'],
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
capture_thread = None                # 数据包捕获线程
stop_capture = False                 # 停止捕获标志

# 进程管理器
manager = None
process_progress = None

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

# 训练进程管理
training_processes = {}

# 全局变量用于跟踪处理状态
processing_status = {
    'is_processing': False,
    'current_file': '',
    'total_files': 0,
    'processed_files': 0
}

# 添加全局变量
flow_buffer = defaultdict(dict)  # 存储每个流的包
flow_timeout = 5  # 流的超时时间（秒）
min_packets = 10  # 最小包数
model_service = None  # 全局模型服务变量
prediction_queue = queue.Queue()  # 预测结果队列

def init_process_manager():
    global manager, process_progress
    if manager is None:
        manager = mp.Manager()
        process_progress = manager.dict({
            'current_file': '',
            'total_rows': 0,
            'processed_rows': 0
        })

# 更新系统状态
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
    """获取可用的数据集列表"""
    try:
        datasets = []
        dataset_dir = app.config['DATASET_FOLDER']
        app.logger.info(f"正在扫描数据集目录: {dataset_dir}")

        if os.path.exists(dataset_dir):
            for item in os.listdir(dataset_dir):
                item_path = os.path.join(dataset_dir, item)
                if os.path.isdir(item_path):
                    # 检查目录中是否包含json文件
                    json_files = [f for f in os.listdir(item_path) if f.endswith('.json')]
                    if json_files:
                        datasets.append({
                            'name': item,
                            'path': item_path,
                            'file_count': len(json_files)
                        })
                        app.logger.info(f"找到数据集: {item}, 包含 {len(json_files)} 个JSON文件")
        else:
            app.logger.error(f"数据集目录不存在: {dataset_dir}")

        app.logger.info(f"共找到 {len(datasets)} 个数据集")
        return jsonify({'status': 'success', 'datasets': datasets})
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

                if filename.lower().endswith(('.pcap', '.pcapng')):
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

@app.route('/process_dataset', methods=['POST'])
def process_dataset():
    try:
        data = request.json
        dataset_directory = data.get('dataset_directory')
        output_directory = data.get('output_directory')
        is_training = data.get('is_training', False)

        if is_training:
            # 调用预训练函数
            pre_train(dataset_directory)

        # 调用 tojson.py 处理数据集
        result = process_dataset(dataset_directory, output_directory)

        return jsonify({
            'status': 'success',
            'message': '预处理完成'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

def process_pcap_file(file_path, output_dir):
    """多进程处理PCAP文件，按流分类保存为JSON格式"""
    try:
        # 初始化处理状态
        processing_status['is_processing'] = True
        processing_status['current_file'] = os.path.basename(file_path)
        processing_status['total_files'] = 1
        processing_status['processed_files'] = 0

        # 1. 读取PCAP文件
        packets = rdpcap(file_path)
        if len(packets) == 0:
            processing_status['is_processing'] = False
            return {'status': 'error', 'message': 'PCAP文件为空'}

        # 2. 准备多进程处理
        num_processes = min(mp.cpu_count(), 4)  # 限制最大进程数
        chunk_size = len(packets) // num_processes + 1
        chunks = [packets[i:i+chunk_size] for i in range(0, len(packets), chunk_size)]

        # 3. 创建进程池
        with mp.Pool(processes=num_processes) as pool:
            # 使用partial固定output_dir参数
            process_func = partial(process_pcap_chunk, output_dir=output_dir)
            # 并行处理数据块
            results = pool.map(process_func, chunks)

        # 4. 合并结果
        merged_flows = {}
        for result in results:
            for flow_key, flow_data in result.items():
                if flow_key not in merged_flows:
                    merged_flows[flow_key] = []
                merged_flows[flow_key].extend(flow_data)

        # 5. 获取对应的CSV文件路径
        csv_file = file_path.replace('.pcap', '.pcap_ISCX.csv')
        if not os.path.exists(csv_file):
            processing_status['is_processing'] = False
            return {'status': 'error', 'message': '未找到对应的CSV文件'}

        # 6. 读取CSV文件获取标签（这部分也可以并行化）
        try:
            df = pd.read_csv(csv_file)
            if 'Flow ID' not in df.columns or 'Label' not in df.columns:
                processing_status['is_processing'] = False
                return {'status': 'error', 'message': 'CSV文件缺少Flow ID或Label列'}

            # 7. 多进程处理标签映射
            label_to_flows = mp.Manager().dict()
            flow_items = list(merged_flows.items())
            flow_chunks = [flow_items[i::num_processes] for i in range(num_processes)]

            with mp.Pool(processes=num_processes) as pool:
                pool.starmap(
                    partial(map_flows_to_labels, df=df, output_dict=label_to_flows),
                    [((chunk,)) for chunk in flow_chunks]
                )

            # 8. 保存结果
            save_results(label_to_flows, output_dir)

            # 更新处理状态
            processing_status['is_processing'] = False
            processing_status['processed_files'] = 1
            return {'status': 'success', 'message': 'PCAP处理完成'}

        except Exception as e:
            processing_status['is_processing'] = False
            app.logger.error(f"处理CSV文件时出错: {str(e)}")
            return {'status': 'error', 'message': f'处理CSV文件时出错: {str(e)}'}

    except Exception as e:
        processing_status['is_processing'] = False
        app.logger.error(f"处理PCAP文件时出错: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def process_pcap_chunk(packets, output_dir):
    """处理PCAP数据块（子进程函数）"""
    flows = {}
    for pkt in packets:
        if not IP in pkt and (TCP in pkt or UDP in pkt):
            continue

        # 获取IP层信息
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto

        # 获取传输层信息
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        else:  # UDP
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # 确保源IP小于目的IP，以统一双向流的键
        if src_ip < dst_ip:
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            length = len(pkt)
        else:
            flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            length = -len(pkt)  # 负值表示反向

        # 生成Flow ID，格式与CSV文件一致：源IP-目的IP-源端口-目的端口-协议
        flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

        if flow_key not in flows:
            flows[flow_key] = []
        flows[flow_key].append((length, float(pkt.time), flow_id))

    return flows

def map_flows_to_labels(flow_chunk, df, output_dict):
    """将流映射到标签（子进程函数）"""
    for flow_key, flow_data in flow_chunk:
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

        matching_rows = df[df['Flow ID'] == flow_id]
        if not matching_rows.empty:
            label = matching_rows.iloc[0]['Label']
            safe_label = label.replace('/', '_').replace('\\', '_')

            # 按时间戳排序
            flow_data.sort(key=lambda x: x[1])

            # 提取特征
            packet_lengths = [float(pkt[0]) for pkt in flow_data]
            time_deltas = [0] + [float(flow_data[i][1] - flow_data[i-1][1])
                               for i in range(1, len(flow_data))]

            flow_entry = {
                "packet_length": packet_lengths,
                "arrive_time_delta": time_deltas
            }

            # 使用线程安全的方式更新共享字典
            if safe_label not in output_dict:
                output_dict[safe_label] = []
            output_dict[safe_label].append(flow_entry)

def save_results(label_to_flows, output_dir):
    """保存最终结果"""
    for label, flows in label_to_flows.items():
        label_dir = os.path.join(output_dir, label)
        os.makedirs(label_dir, exist_ok=True)

        output_file = os.path.join(label_dir, f"{label}.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(flows, f, ensure_ascii=False, indent=2)
        app.logger.info(f"已保存{len(flows)}条流到{output_file}")
        app.logger.error(f"处理PCAP数据块时出错: {str(e)}")
        return {}

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

# @app.route('/get_models')
# def get_models():
#     """获取所有已训练好的模型"""
#     try:
#         models = []
#         model_dir = app.config['MODEL_FOLDER']
#         if os.path.exists(model_dir):
#             for model_name in os.listdir(model_dir):
#                 model_path = os.path.join(model_dir, model_name)
#                 if os.path.isdir(model_path):
#                     # 检查是否存在模型文件
#                     model_files = [f for f in os.listdir(model_path) if f.endswith('.h5') or f.endswith('.pth')]
#                     if model_files:
#                         models.append({
#                             'name': model_name,
#                             'path': model_path,
#                             'file_count': len(model_files)
#                         })
#         return jsonify({'status': 'success', 'models': models})
#     except Exception as e:
#         app.logger.error(f"获取模型列表错误: {str(e)}")
#         return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_available_models')
def get_available_models():
    """获取可用的模型列表"""
    try:
        models = []
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        app.logger.info(f"正在扫描模型目录: {models_dir}")

        # 遍历models目录下的子目录
        for model_type in ['dl', 'ml']:
            type_dir = os.path.join(models_dir, model_type)
            if os.path.exists(type_dir):
                app.logger.info(f"扫描 {model_type} 类型模型")
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
                            app.logger.info(f"找到模型: {model_name} ({model_type})")

        app.logger.info(f"共找到 {len(models)} 个模型")
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

        # 获取虚拟环境路径
        venv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.venv37')
        if not os.path.exists(venv_path):
            return jsonify({
                'status': 'error',
                'message': '虚拟环境不存在'
            })

        # 构建训练命令
        python_path = os.path.join(venv_path, 'Scripts', 'python.exe')
        cmd = [python_path, f'models/dl/{model_name}/{model_name}_main_model.py', '--dataset', dataset_name]


        app.logger.info(f"使用虚拟环境执行命令: {' '.join(cmd)}")

        # 创建字典保存训练进程的相关信息
        process_info = {
            'model': model_name,  # 训练的模型名称
            'dataset': dataset_name,  # 使用的数据集名称
            'start_time': datetime.now().isoformat(),  # 训练开始时间（ISO格式）
            'progress': 0,  # 训练进度初始化为0
            'metrics': {  # 用于保存训练过程中的各项指标
                'steps': [],  # 训练步数
                'train_losses': [],  # 训练损失值
                'train_accuracies': [],  # 训练准确率
                'dev_losses': [],  # 验证损失值
                'dev_accuracies': []  # 验证准确率
            }
        }

        # 使用subprocess启动训练进程
        process = subprocess.Popen(
            cmd,  # 要执行的命令
            stdout=subprocess.PIPE,  # 捕获标准输出
            stderr=subprocess.PIPE,  # 捕获标准错误
            text=True,  # 以文本模式处理输出
            bufsize=1,  # 行缓冲
            universal_newlines=True  # 统一换行符
        )

        # 将进程对象保存到进程信息字典中
        process_info['process'] = process
        # 将进程信息存入全局字典，以进程ID为键
        training_processes[process.pid] = process_info

        # 启动一个守护线程来监控训练输出
        threading.Thread(
            target=monitor_training_output,  # 监控函数
            args=(process, process.pid, process_info),  # 传入参数
            daemon=True  # 设置为守护线程
        ).start()

        app.logger.info(f"训练进程已启动，PID: {process.pid}")
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

def monitor_training_output(process, pid, process_info):
    """监控训练进程的输出"""
    try:
        while True:
            # 读取进程输出的一行
            line = process.stdout.readline()
            # 如果没有输出且进程已结束，则退出循环
            if not line and process.poll() is not None:
                break
            if line:
                # 解析训练进度
                if 'Training:' in line:
                    # 提取进度百分比
                    progress = line.split('|')[0].split(':')[1].strip()
                    if '%' in progress:
                        # 转换为浮点数并更新进度
                        progress = float(progress.replace('%', ''))
                        process_info['progress'] = progress

                # 解析训练指标
                if '[Step=' in line:
                    step = int(line.split('[Step=')[1].split(']')[0])
                    if 'TRAIN batch' in line:
                        loss = float(line.split('loss: ')[1].split(',')[0])
                        accuracy = float(line.split('accuracy: ')[1].strip())
                        process_info['metrics']['steps'].append(step)
                        process_info['metrics']['train_losses'].append(loss)
                        process_info['metrics']['train_accuracies'].append(accuracy)
                    elif 'DEV batch' in line:
                        loss = float(line.split('loss: ')[1].split(',')[0])
                        accuracy = float(line.split('accuracy: ')[1].strip())
                        process_info['metrics']['dev_losses'].append(loss)
                        process_info['metrics']['dev_accuracies'].append(accuracy)

                # 解析评估结果
                if 'precision' in line and 'recall' in line:
                    # 解析分类报告
                    metrics = parse_classification_report(line)
                    process_info['evaluation'] = metrics

                # 更新全局训练状态
                training_status['progress'] = process_info.get('progress', 0)
                training_status['metrics'] = process_info.get('metrics', {})
                if 'evaluation' in process_info:
                    training_status['evaluation'] = process_info['evaluation']

    except Exception as e:
        app.logger.error(f"监控训练输出时出错: {str(e)}")

def parse_classification_report(report):
    """解析分类报告"""
    metrics = {}
    lines = report.split('\n')
    for line in lines:
        if line.strip():
            parts = line.split()
            if len(parts) >= 5:
                try:
                    metrics[parts[0]] = {
                        'precision': float(parts[1]),
                        'recall': float(parts[2]),
                        'f1_score': float(parts[3]),
                        'support': int(parts[4])
                    }
                except ValueError:
                    continue
    return metrics

@app.route('/training_progress')
def training_progress():
    """获取训练进度"""
    pid = request.args.get('pid', type=int)
    def generate(pid):
        try:
            if not pid or pid not in training_processes:
                yield f"data: {json.dumps({'status': 'error', 'message': '无效的训练进程ID'})}\n\n"
                return

            process_info = training_processes[pid]
            while True:
                if process_info['process'].poll() is not None:
                    # 训练已完成
                    yield f"data: {json.dumps({'status': 'completed', 'progress': process_info.get('progress', 0), 'metrics': process_info.get('metrics', {}), 'evaluation': process_info.get('evaluation', {})})}\n\n"
                    break
                else:
                    # 训练进行中
                    yield f"data: {json.dumps({'status': 'training', 'progress': process_info.get('progress', 0), 'metrics': process_info.get('metrics', {}), 'evaluation': process_info.get('evaluation', {})})}\n\n"
                time.sleep(1)  # 每秒更新一次
        except Exception as e:
            app.logger.error(f"获取训练进度时出错: {str(e)}")
            yield f"data: {json.dumps({'status': 'error', 'message': str(e)})}\n\n"

    return Response(
        stream_with_context(generate(pid)),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

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
        csv_dir = os.path.join(app.config['OUTPUT_FOLDER'], dataset_name)
        os.makedirs(csv_dir, exist_ok=True)
        dataset_dir = os.path.join(app.config['DATASET_FOLDER'], 'train_data', dataset_name)
        os.makedirs(dataset_dir, exist_ok=True)

        # 3. 处理文件上传
        processed_files = []
        pcap_files = []  # 存储所有PCAP文件路径
        for file in request.files.getlist('files[]'):
            if not file.filename:
                continue

            filename = secure_filename(file.filename)
            if not filename:  # 安全过滤
                continue

            file_path = os.path.join(originaldata_dir, filename)
            file.save(file_path)
            processed_files.append(filename)

            # 记录PCAP文件
            if filename.lower().endswith(('.pcap', '.pcapng')):
                pcap_files.append(file_path)

        # 4. 处理所有PCAP文件
        result = process_pcap_file(originaldata_dir, csv_dir, dataset_dir)
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

def load_model(model_name):
    """加载指定的模型"""
    global model_service
    try:
        if model_name == 'fsnet':
            # 初始化FSNet模型
            model_service = FSNetModel('train_data_test4', randseed=128, splitrate=0.6, max_len=200)
            # 确保模型目录存在
            model_dir = os.path.join('data', 'fsnet_train_data_test4_model', 'log')
            if not os.path.exists(model_dir):
                app.logger.error(f"模型目录不存在: {model_dir}")
                return False
            # 检查是否有训练好的模型
            ckpt = tf.train.get_checkpoint_state(model_dir)
            if not ckpt or not ckpt.model_checkpoint_path:
                app.logger.error("未找到训练好的模型")
                return False
            return True
        else:
            app.logger.error(f"不支持的模型类型: {model_name}")
            return False
    except Exception as e:
        app.logger.error(f"加载模型失败: {str(e)}")
        return False


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
    packet_length = len(packet)  # 获取数据包字节数
    current_time = time.time()

    # 获取包长
    packet_length = len(packet)
    # 确定包方向
    if src_ip < dst_ip:
        packet_length = packet_length
    else:
        packet_length = -packet_length

    # 初始化流统计（新增first_packet_time字段）
    if flow_id not in flow_buffer:
        flow_buffer[flow_id] = {
            'packets': [],
            'bytes': 0,
            'first_packet_time': current_time,  # 记录第一个包到达时间
            'start_time': current_time,
            'last_update': current_time,
            'last_byte_time': current_time,
            'bytes_per_second': 0
        }

    flow_buffer[flow_id]['packets'].append(packet_length)
    flow_buffer[flow_id]['last_update'] = current_time

    # 计算实时流量
    time_diff = current_time - flow_buffer[flow_id]['last_byte_time']
    if time_diff > 0:
        flow_buffer[flow_id]['bytes_per_second'] = len(packet) / time_diff
    flow_buffer[flow_id]['last_byte_time'] = current_time
    flow_buffer[flow_id]['last_update'] = current_time

    # 检查流是否满足预测条件
    if len(flow_buffer[flow_id]['packets']) >= min_packets:
        try:
            # 确保flow_data是一个列表
            flow_data = [flow_buffer[flow_id]['packets']]
            if not isinstance(flow_data, list):
                flow_data = [flow_data]

            # 进行预测
            prediction = model_service.logit_online(flow_data)
            pred_label = int(np.argmax(prediction))
            confidence = float(np.max(prediction[0]))  # 取最大概率作为置信度

            # 计算响应时间（当前时间 - 第一个包到达时间）
            response_time = current_time - flow_buffer[flow_id]['first_packet_time']

            # 将预测结果放入队列
            prediction_queue.put({
                'flow_id': flow_id,
                'prediction': pred_label,
                'confidence': confidence,
                'timestamp': current_time,
                'packet_count': len(flow_buffer[flow_id]['packets']),
                'bytes_per_second': flow_buffer[flow_id]['bytes_per_second'],
                'response_time': response_time,  # 新增响应时间
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol
            })
            # 清空该流
            del flow_buffer[flow_id]
        except Exception as e:
            app.logger.error(f"预测失败: {str(e)}")
            # 如果预测失败，也清空该流
            del flow_buffer[flow_id]

    # 清理超时的流
    for fid in list(flow_buffer.keys()):
        if current_time - flow_buffer[fid]['last_update'] > flow_timeout:
            del flow_buffer[fid]

def start_packet_capture(interface):
    """开始捕获数据包"""
    def packet_handler(packet):
        if stop_capture:
            return
        process_packet(packet)

    sniff(iface=interface, prn=packet_handler, store=0)

@app.route('/realtime_monitor', methods=['GET', 'POST'])
def realtime_monitor():
    global is_monitoring, min_packets, capture_thread, stop_capture, model_service

    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')

        if action == 'start':
            interfaces = data.get('interfaces')
            model_name = data.get('model')
            min_packets = data.get('min_packets', 10)

            if not model_name or not interfaces:
                return jsonify({'status': 'error', 'message': '缺少模型或接口参数'})

            # 加载模型
            if not load_model(model_name):
                return jsonify({'status': 'error', 'message': '模型加载失败'})

            is_monitoring = True
            stop_capture = False
            capture_thread = threading.Thread(target=start_packet_capture, args=(interfaces[0],), daemon=True)
            capture_thread.start()

            return jsonify({'status': 'success', 'message': '监测已启动'})

        elif action == 'stop':
            is_monitoring = False
            stop_capture = True
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=1.0)

            # ✅ 卸载模型
            if model_service:
                try:
                    if hasattr(model_service, 'close'):
                        model_service.close()  # 如果你定义了 close 方法
                except Exception as e:
                    app.logger.warning(f"模型关闭异常: {str(e)}")
                model_service = None

            # ✅ 清理 TensorFlow flags 防止冲突
            try:
                from tensorflow.python.platform import flags
                flags.FLAGS.__dict__['__flags'].clear()
                flags.FLAGS.__dict__['__parsed'] = False
            except Exception as e:
                app.logger.warning(f"清理 flags 失败: {str(e)}")

            return jsonify({'status': 'success', 'message': '监测已停止并清理模型'})

        return jsonify({'status': 'error', 'message': '未知操作'})

    # GET 请求返回状态页面
    system_status = {
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    return render_template('realtime_monitor.html', system_status=system_status)



# @app.route('/get_predictions')
# def get_predictions():
#     """获取预测结果（确保包含response_time）"""
#     predictions = []
#     while not prediction_queue.empty():
#         pred = prediction_queue.get()
#         # 设置默认值
#         pred.setdefault('bytes_per_second', 0)
#         pred.setdefault('response_time', 0)  # 新增
#         predictions.append(pred)

#     return jsonify({
#         'status': 'success',
#         'predictions': predictions
#     })
@app.route('/get_predictions')
def get_predictions():
    """获取预测结果，并统计各个类别的数量"""
    predictions = []
    label_counts = defaultdict(int)  # 用于统计每种标签的数量

    # 从模型目录读取标签映射
    label_mapping = {
        0: 'BENIGN',
        1: 'Bot',
        2: 'DDoS',
        3: 'PortScan',
        -1: 'UNKNOWN'
    }

    while not prediction_queue.empty():
        pred = prediction_queue.get()
        label = pred['prediction']
        label_name = label_mapping.get(label, 'UNKNOWN')

        # 设置分类名称
        pred['label_name'] = label_name
        label_counts[label_name] += 1

        # 设置默认值
        pred.setdefault('bytes_per_second', 0)
        pred.setdefault('response_time', 0)
        predictions.append(pred)

    return jsonify({
        'status': 'success',
        'predictions': predictions,
        'label_counts': dict(label_counts)  # 转换为普通字典
    })


@app.route('/model_status')
def model_status():
    return jsonify({
        'loaded': model_service is not None
    })

@app.route('/capture_status')
def capture_status():
    return jsonify({
        'capturing': is_monitoring
    })

if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # 初始化进程管理器
    init_process_manager()
    app.run(debug=True)
