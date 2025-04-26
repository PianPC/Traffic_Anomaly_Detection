import json
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import os

def preprocess_flow_id(flow_id):
    """预处理flow_id以匹配CSV格式"""
    parts = flow_id.split('-')
    if len(parts) == 5:  # src_ip:src_port-dst_ip:dst_port-protocol
        src_ip_port, dst_ip_port, protocol = parts
        src_ip, src_port = src_ip_port.split(':')
        dst_ip, dst_port = dst_ip_port.split(':')

        # 修改目的IP为192.168.229.35
        dst_ip = '192.168.229.35'

        # 重新构建flow_id
        return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
    return flow_id

def evaluate_predictions(json_path, csv_path):
    """评估预测结果"""
    # 1. 加载JSON预测结果
    with open(json_path, 'r') as f:
        predictions = json.load(f)

    # 2. 加载CSV数据并预处理
    df = pd.read_csv(csv_path)

    # 3. 构建预测结果字典
    pred_dict = {}
    for pred in predictions:
        flow_id = preprocess_flow_id(pred['flow_id'])
        pred_dict[flow_id] = pred['label']

    # 4. 匹配并评估
    y_true = []
    y_pred = []

    for _, row in df.iterrows():
        flow_id = row['Flow ID']
        if flow_id in pred_dict:
            y_true.append(row['Label'])
            y_pred.append(pred_dict[flow_id])

    if not y_true:
        print("没有匹配的流量记录")
        return

    # 5. 计算评估指标
    print("\n评估结果:")
    print(f"准确率: {accuracy_score(y_true, y_pred):.4f}")

    print("\n混淆矩阵:")
    print(confusion_matrix(y_true, y_pred))

    print("\n分类报告:")
    print(classification_report(y_true, y_pred))

if __name__ == '__main__':
    # 示例用法
    json_file = input("请输入JSON文件路径: ").strip('"')
    csv_file = "E:\\workplace\\Code\\VSCodeProject\\traffic_anomaly_detection\\output\\Friday-WorkingHours.csv"

    if not os.path.exists(json_file):
        print(f"JSON文件不存在: {json_file}")
    elif not os.path.exists(csv_file):
        print(f"CSV文件不存在: {csv_file}")
    else:
        evaluate_predictions(json_file, csv_file)
