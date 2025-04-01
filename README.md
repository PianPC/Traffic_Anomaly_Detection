# 流量异常检测系统

这是一个基于机器学习的网络流量异常检测系统，提供实时监测、历史数据分析和模型训练功能。

## 功能特点

- 实时流量监测：支持选择网络接口和检测模型，实时分析网络流量
- 历史数据分析：支持上传PCAP或CSV格式的历史数据进行分析
- 模型训练：支持多种深度学习模型的训练和评估
- 可视化界面：提供直观的数据展示和交互界面

## 支持的模型

- FS-Net：基于流序列的加密流量分类模型
- GraphDapp：基于图神经网络的DApp识别模型
- AppNet：移动应用流量分类模型

## 安装说明

1. 克隆项目到本地：
```bash
git clone https://github.com/yourusername/traffic_anomaly_detection.git
cd traffic_anomaly_detection
```

2. 创建并激活虚拟环境：
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用说明

1. 启动Web服务：
```bash
cd web
python app.py
```

2. 在浏览器中访问：
```
http://localhost:5000
```

### 实时监测

1. 选择要使用的检测模型
2. 选择要监控的网络接口
3. 点击"开始监测"按钮
4. 查看实时流量统计和异常检测结果

### 历史数据分析

1. 上传PCAP或CSV格式的历史数据文件
2. 选择要使用的分析模型
3. 点击"开始分析"按钮
4. 查看分析结果和详细报告

### 模型训练

1. 选择要训练的模型类型
2. 选择训练数据集
3. 设置训练参数（轮数、批次大小、学习率等）
4. 点击"开始训练"按钮
5. 查看训练进度和评估指标

## 项目结构

```
traffic_anomaly_detection/
├── web/                    # Web应用目录
│   ├── app.py             # Flask应用主文件
│   ├── static/            # 静态文件目录
│   └── templates/         # HTML模板目录
├── models/                # 模型目录
│   ├── fsnet/            # FS-Net模型
│   ├── graphdapp/        # GraphDapp模型
│   └── appnet/           # AppNet模型
├── dataset/              # 数据集目录
├── requirements.txt      # 项目依赖
└── README.md            # 项目说明文档
```

## 注意事项

1. 实时监测功能需要管理员权限才能访问网络接口
2. 建议使用虚拟环境运行项目，避免依赖冲突
3. 训练大型模型时可能需要较长时间，请耐心等待
4. 确保有足够的磁盘空间存储数据集和模型文件

## 贡献指南

欢迎提交Issue和Pull Request来帮助改进项目。

## 许可证

本项目采用MIT许可证。详见LICENSE文件。
