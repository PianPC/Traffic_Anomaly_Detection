import json
import csv
import os

def calculate_accuracy(json_path, csv_path):
    # 检查 JSON 文件是否存在
    if not os.path.exists(json_path):
        return None, None, None  # 返回 None 表示文件不存在

    # 读取 JSON 文件
    with open(json_path, 'r') as f:
        predictions = json.load(f)

    # 读取 CSV 文件并构建 flow_id 到 label 的映射
    flow_id_to_label = {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            flow_id = row['Flow ID']
            label = row['Label']
            flow_id_to_label[flow_id] = label

    # 初始化计数器
    total = 0
    right = 0

    # 遍历预测结果
    for pred in predictions:
        pred_flow_id = pred['flow_id']
        pred_label = pred['label']

        # 检查 flow_id 是否在 CSV 中
        if pred_flow_id in flow_id_to_label:
            total += 1
            true_label = flow_id_to_label[pred_flow_id]

            # 检查预测标签是否匹配
            if pred_label == true_label:
                right += 1

    # 计算准确率
    if total > 0:
        accuracy = (right / total) * 100
    else:
        accuracy = 0.0

    return accuracy, total, right

# 文件路径
csv_path = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\output\Friday-WorkingHours-flow_id_label.csv"
original_path = r"E:\workplace\Code\VSCodeProject\traffic_anomaly_detection\output\test1.json"
dir_path = os.path.dirname(original_path)

change_part = range(1,7)

# 遍历所有可能的组合
for n in change_part:
    # 格式化文件名，保留一位小数
    new_name = f"test{n}.json"
    new_path = os.path.join(dir_path, new_name)

    # 检查文件是否存在
    if not os.path.exists(new_path):
        print(f"文件 {new_name} 不存在，跳过...")
        continue  # 跳过不存在的文件

    # 计算准确率
    accuracy, total, right = calculate_accuracy(new_path, csv_path)

    # 打印结果
    print(f"\n文件名: {new_name}")
    print(f"匹配到的 flow_id 数量: {total}")
    print(f"正确预测的数量: {right}")
    print(f"准确率: {accuracy:.2f}%")


# accuracy, total, right = calculate_accuracy(original_path, csv_path)

# # 打印结果
# print(f"文件：{original_path}")
# print(f"匹配到的 flow_id 数量: {total}")
# print(f"正确预测的数量: {right}")
# print(f"准确率: {accuracy:.2f}%")
