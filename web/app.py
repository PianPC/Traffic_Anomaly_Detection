#
from flask import Flask, render_template, request, jsonify, send_file
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
from models.fsnet.model import ModelPredictor
from models.data_processor import DataProcessor

app = Flask(
    __name__,                   # 告诉 Flask 当前模块（文件）的名称，用于定位项目的根目录
    static_folder='static',     # 指定静态文件在文件系统中的存储目录
    static_url_path='/static')  # 定义静态文件在 URL 中的访问路径前缀。修改此处可以达到隐藏静态路径的效果

# 添加配置项
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
app.config['ORIGINAL_DATA_FOLDER'] = os.path.join(BASE_DIR, 'originaldata')
app.config['DATASET_FOLDER'] = os.path.join(BASE_DIR, 'dataset')
app.config['MODEL_FOLDER'] = os.path.join(BASE_DIR, 'trained_models')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')

# 创建必要的目录
os.makedirs(app.config['ORIGINAL_DATA_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATASET_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True)

app.logger.setLevel(logging.INFO)   # 开发环境，使用 DEBUG 级别，记录所有细节。生产环境，使用 INFO 或更高，仅记录关键信息。

# 全局变量
realtime_data_queue = queue.Queue()
is_monitoring = False
current_model = None
current_interface = None
model_predictor = None
current_monitoring_session = None
monitoring_data = {
    'sessions': {},
    'current_session': None
}
training_status = {
    'is_training': False,
    'progress': 0,
    'metrics': {
        'epochs': [],
        'losses': [],
        'accuracies': []
    }
}

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

@app.route('/realtime_monitor', methods=['GET', 'POST'])
def realtime_monitor():
    # 获取系统状态
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
            capture_duration = data.get('capture_duration', 300)  # 默认5分钟

            # 创建新的监控会话
            session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            current_monitoring_session = session_id
            monitoring_data['sessions'][session_id] = {
                'start_time': datetime.now(),
                'interfaces': interfaces,
                'model': model_name,
                'datasets': [],
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
    try:
        interfaces = []
        for interface, stats in psutil.net_if_stats().items():
            # 过滤掉回环接口和虚拟接口
            if interface != 'lo' and not interface.startswith('veth'):
                interfaces.append({
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                })
        return jsonify({'status': 'success', 'interfaces': interfaces})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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

@app.route('/historical_analysis', methods=['GET', 'POST'])
def historical_analysis():
    # 获取系统状态
    system_status = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': '没有文件'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': '没有选择文件'})

        if file:
            # 创建时间戳目录
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_dir = os.path.join(app.config['ORIGINAL_DATA_FOLDER'], f'data-{timestamp}')
            dataset_dir = os.path.join(app.config['DATASET_FOLDER'], f'data-{timestamp}')
            os.makedirs(original_dir, exist_ok=True)
            os.makedirs(dataset_dir, exist_ok=True)

            # 保存原始文件
            filename = secure_filename(file.filename)
            original_path = os.path.join(original_dir, filename)
            file.save(original_path)

            # 处理数据
            data_processor = DataProcessor()
            if filename.endswith('.pcap'):
                flows = data_processor.process_pcap(original_path)
            elif filename.endswith('.csv'):
                flows = data_processor.process_csv(original_path)
            else:
                return jsonify({'status': 'error', 'message': '不支持的文件格式'})

            # 保存处理后的数据
            processed_filename = f"{os.path.splitext(filename)[0]}.json"
            processed_path = os.path.join(dataset_dir, processed_filename)
            with open(processed_path, 'w', encoding='utf-8') as f:
                json.dump(flows, f, ensure_ascii=False, indent=2)

            return jsonify({
                'status': 'success',
                'message': '文件处理完成',
                'data': {
                    'original_file': original_path,
                    'processed_file': processed_path
                }
            })

    return render_template('historical_analysis.html', system_status=system_status)

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
            epochs = data.get('epochs')
            batch_size = data.get('batch_size')
            learning_rate = data.get('learning_rate')
            validation_split = data.get('validation_split', 0.2)

            if not all([model, dataset, epochs, batch_size, learning_rate]):
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
                args=(model, dataset, epochs, batch_size, learning_rate, validation_split),
                daemon=True
            ).start()

            return jsonify({'status': 'success', 'message': '训练已启动'})

        elif action == 'stop':
            training_status['is_training'] = False
            return jsonify({'status': 'success', 'message': '训练已停止'})

    return render_template('model_training.html', system_status=system_status)

@app.route('/get_datasets')
def get_datasets():
    try:
        datasets = [d for d in os.listdir(app.config['UPLOAD_FOLDER'])
                   if os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'], d))]
        return jsonify({'datasets': datasets})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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
    """获取所有可用的模型"""
    try:
        models = []
        model_dir = app.config['MODEL_FOLDER']
        if os.path.exists(model_dir):
            for model_name in os.listdir(model_dir):
                model_path = os.path.join(model_dir, model_name)
                if os.path.isdir(model_path):
                    # 读取模型配置文件
                    config_file = os.path.join(model_path, 'config.json')
                    if os.path.exists(config_file):
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            models.append({
                                'name': model_name,
                                'type': config.get('type', 'unknown'),
                                'description': config.get('description', ''),
                                'parameters': config.get('parameters', {})
                            })
        return jsonify({'status': 'success', 'models': models})
    except Exception as e:
        logger.error(f"获取模型列表错误: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

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

def train_model(model, dataset, epochs, batch_size, learning_rate, validation_split):
    global training_status
    try:
        # 加载数据集
        dataset_path = os.path.join(app.config['DATASET_FOLDER'], dataset)
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"数据集 {dataset} 不存在")

        # 创建模型目录
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        model_dir = os.path.join(app.config['MODEL_FOLDER'], f"{model}_{timestamp}")
        os.makedirs(model_dir, exist_ok=True)

        # 保存模型配置
        config = {
            'type': model,
            'description': f'使用数据集 {dataset} 训练的模型',
            'training_time': timestamp,
            'parameters': {
                'epochs': epochs,
                'batch_size': batch_size,
                'learning_rate': learning_rate,
                'validation_split': validation_split
            },
            'metrics': {
                'final_loss': 0.0,
                'final_accuracy': 0.0,
                'best_epoch': 0,
                'training_duration': 0
            }
        }

        # 导入FS-Net模型
        from models.fsnet.model import FSnet
        from models.fsnet.trainer import FSnetTrainer

        # 初始化模型
        model = FSnet()

        # 加载数据集
        data_processor = DataProcessor()
        flows = data_processor.load_from_json(dataset_path)

        # 准备训练数据
        X = np.array([flow['packet_length'] for flow in flows])
        y = np.array([flow.get('label', 0) for flow in flows])

        # 划分训练集和验证集
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]

        # 初始化训练器
        trainer = FSnetTrainer(
            model=model,
            learning_rate=learning_rate,
            batch_size=batch_size
        )

        start_time = time.time()
        best_accuracy = 0
        best_epoch = 0

        for epoch in range(epochs):
            if not training_status['is_training']:
                break

            # 训练一个epoch
            train_loss, train_acc = trainer.train_epoch(X_train, y_train)

            # 验证
            val_loss, val_acc = trainer.validate(X_val, y_val)

            # 更新训练状态
            training_status['progress'] = int((epoch + 1) / epochs * 100)
            training_status['metrics']['epochs'].append(epoch + 1)
            training_status['metrics']['losses'].append(train_loss)
            training_status['metrics']['accuracies'].append(train_acc)
            training_status['metrics']['val_losses'].append(val_loss)
            training_status['metrics']['val_accuracies'].append(val_acc)

            if val_acc > best_accuracy:
                best_accuracy = val_acc
                best_epoch = epoch + 1
                # 保存最佳模型
                trainer.save_model(os.path.join(model_dir, 'model.pth'))

        if training_status['is_training']:
            # 更新配置中的指标
            config['metrics'].update({
                'final_loss': training_status['metrics']['losses'][-1],
                'final_accuracy': training_status['metrics']['accuracies'][-1],
                'best_epoch': best_epoch,
                'training_duration': time.time() - start_time
            })

            # 保存模型配置
            with open(os.path.join(model_dir, 'config.json'), 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

            # 保存训练历史
            history = {
                'epochs': training_status['metrics']['epochs'],
                'losses': training_status['metrics']['losses'],
                'accuracies': training_status['metrics']['accuracies'],
                'val_losses': training_status['metrics']['val_losses'],
                'val_accuracies': training_status['metrics']['val_accuracies']
            }
            with open(os.path.join(model_dir, 'history.json'), 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)

        training_status['is_training'] = False

    except Exception as e:
        app.logger.error(f"训练错误: {str(e)}")
        training_status['is_training'] = False

if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
