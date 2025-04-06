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
from data_processor import DataConverter

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
app.config['MAX_CONTENT_LENGTH'] = None     # 16 * 1024 * 1024  # 上传文件大小限制（16MB）
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

@app.route('/get_datasets')
def get_datasets():
    """获取可用的数据集列表（文件夹）"""
    try:
        datasets = []
        dataset_dir = app.config['DATASET_FOLDER']
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
        return jsonify({'status': 'success', 'datasets': datasets})
    except Exception as e:
        app.logger.error(f"获取数据集列表错误: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/historical_analysis', methods=['GET', 'POST'])
def historical_analysis():
    # 获取系统状态
    system_status = {
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_interfaces': psutil.net_if_stats(),
        'running_processes': len(psutil.pids())
    }

    if request.method == 'POST':
        if 'file' not in request.files:
            app.logger.error("没有文件被上传")
            return jsonify({'status': 'error', 'message': '没有文件'})

        file = request.files['file']
        if file.filename == '':
            app.logger.error("文件名为空")
            return jsonify({'status': 'error', 'message': '没有选择文件'})

        if file:
            try:
                # 检查文件大小
                file.seek(0, 2)  # 移动到文件末尾
                file_size = file.tell()  # 获取文件大小
                file.seek(0)  # 重置文件指针到开始

                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    app.logger.error(f"文件大小超过限制: {file_size} bytes")
                    return jsonify({'status': 'error', 'message': '文件大小超过限制'})

                # 创建时间戳目录
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                dataset_name = f"data_{timestamp}"

                # 创建原始数据目录
                original_dir = os.path.join(app.config['ORIGINAL_DATA_FOLDER'], dataset_name)
                os.makedirs(original_dir, exist_ok=True)
                app.logger.info(f"创建原始数据目录: {original_dir}")

                # 创建数据集目录
                dataset_dir = os.path.join(app.config['DATASET_FOLDER'], dataset_name)
                os.makedirs(dataset_dir, exist_ok=True)
                app.logger.info(f"创建数据集目录: {dataset_dir}")

                # 保存原始文件
                filename = secure_filename(file.filename)
                original_path = os.path.join(original_dir, filename)
                file.save(original_path)
                app.logger.info(f"保存原始文件: {original_path}")

                # 检查文件是否成功保存
                if not os.path.exists(original_path):
                    app.logger.error(f"文件保存失败: {original_path}")
                    return jsonify({'status': 'error', 'message': '文件保存失败'})

                # 调用数据处理脚本
                try:
                    converter = DataConverter()
                    # 处理单个文件
                    if filename.endswith('.pcap'):
                        flows = converter.process_pcap(original_path)
                    elif filename.endswith('.csv'):
                        flows = converter.process_csv(original_path)
                    else:
                        return jsonify({'status': 'error', 'message': '不支持的文件格式'})

                    if not flows:
                        return jsonify({'status': 'error', 'message': '数据处理失败：没有提取到有效数据'})

                    # 保存处理后的数据
                    processed_filename = f"{os.path.splitext(filename)[0]}.json"
                    processed_path = os.path.join(dataset_dir, processed_filename)
                    with open(processed_path, 'w', encoding='utf-8') as f:
                        json.dump(flows, f, ensure_ascii=False, indent=2)
                    app.logger.info(f"保存处理后的数据到: {processed_path}")

                    # 保存数据集信息
                    info = {
                        'name': dataset_name,
                        'original_file': original_path,
                        'processed_file': processed_path,
                        'process_time': datetime.now().isoformat(),
                        'file_count': 1,
                        'flow_count': len(flows),
                        'total_packets': sum(len(flow['packet_length']) for flow in flows)
                    }
                    info_path = os.path.join(dataset_dir, 'info.json')
                    with open(info_path, 'w', encoding='utf-8') as f:
                        json.dump(info, f, ensure_ascii=False, indent=2)

                    return jsonify({
                        'status': 'success',
                        'message': '文件处理完成',
                        'data': {
                            'original_file': original_path,
                            'processed_file': processed_path,
                            'dataset_name': dataset_name,
                            'flow_count': len(flows),
                            'total_packets': sum(len(flow['packet_length']) for flow in flows)
                        }
                    })

                except Exception as e:
                    app.logger.error(f"数据处理失败: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'数据处理失败: {str(e)}'})

            except Exception as e:
                app.logger.error(f"文件处理错误: {str(e)}", exc_info=True)
                return jsonify({'status': 'error', 'message': f'文件处理错误: {str(e)}'})

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
        models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'models')
        available_models = []

        # 检查dl和ml目录
        for model_type in ['dl', 'ml']:
            type_dir = os.path.join(models_dir, model_type)
            if os.path.exists(type_dir):
                # 获取所有子目录
                for model_name in os.listdir(type_dir):
                    model_path = os.path.join(type_dir, model_name)
                    if os.path.isdir(model_path):
                        # 检查是否存在对应的主模型文件
                        main_model_file = os.path.join(model_path, f"{model_name}_main_model.py")
                        if os.path.exists(main_model_file):
                            available_models.append({
                                'name': model_name,
                                'type': model_type
                            })

        return jsonify({
            'status': 'success',
            'models': available_models
        })

    except Exception as e:
        app.logger.error(f"获取可用模型列表时出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

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
    app.run(debug=True)
