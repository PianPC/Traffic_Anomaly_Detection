import torch
import torch.nn as nn
import numpy as np
import os
import json
from models.data_processor import DataProcessor

class FSnet(nn.Module):
    def __init__(self, input_size=100, hidden_size=128, num_classes=2):
        super(FSnet, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        out = self.fc(lstm_out[:, -1, :])
        return out

class ModelPredictor:
    def __init__(self, model_path):
        self.model_path = model_path
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # 加载模型配置
        with open(os.path.join(model_path, 'config.json'), 'r', encoding='utf-8') as f:
            self.config = json.load(f)

        # 初始化模型
        self.model = FSnet(
            input_size=self.config['parameters'].get('input_size', 100),
            hidden_size=self.config['parameters'].get('hidden_size', 128),
            num_classes=self.config['parameters'].get('num_classes', 2)
        )
        self.model.to(self.device)

        # 加载模型权重
        self.model.load_state_dict(torch.load(os.path.join(model_path, 'model.pth')))
        self.model.eval()

        # 初始化数据处理器
        self.data_processor = DataProcessor(
            max_packet_length=self.config['parameters'].get('max_packet_length', 100)
        )

    def preprocess_packets(self, packets):
        """预处理数据包"""
        processed_data = self.data_processor.process_packets(packets)
        # 转换为模型输入格式
        x = torch.tensor(processed_data['packet_length'], dtype=torch.float32).unsqueeze(0)
        return x

    def predict(self, packets):
        """预测数据包类型"""
        with torch.no_grad():
            x = self.preprocess_packets(packets)
            x = x.to(self.device)
            output = self.model(x)
            _, predicted = torch.max(output.data, 1)
            return predicted.item()

    def predict_batch(self, flows):
        """批量预测"""
        predictions = []
        for flow in flows:
            x = self.preprocess_packets(flow)
            x = x.to(self.device)
            with torch.no_grad():
                output = self.model(x)
                _, predicted = torch.max(output.data, 1)
                predictions.append(predicted.item())
        return predictions
