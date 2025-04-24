# 使用FPR数据计算
fpr_data = {
    "-1": 0.02969598722230541,
    "0": 0.07724608206723292,
    "1": 0.0629300408647969,
    "2": 0.0001825967077813587,
    "3": 0.0
}

# 初始化混淆矩阵
confusion_matrix = np.zeros((4, 4))

# 计算每个类别的TP和FP
for i in range(4):
    class_data = data["classification_report"][str(i)]
    TP = class_data["recall"] * class_data["support"]
    FP = fpr_data[str(i)] * (total_samples - class_data["support"])

    confusion_matrix[i, i] = TP

    # 计算FN
    FN = class_data["support"] - TP

    # 计算TN
    TN = total_samples - class_data["support"] - FP

    # 分配FN到其他类别
    # 这里可以更智能地分配，比如根据FPR比例
    for j in range(4):
        if j != i:
            confusion_matrix[i, j] = FN * (fpr_data[str(j)] / (1 - fpr_data[str(i)]))

# 确保每行总和等于support
for i in range(4):
    row_sum = np.sum(confusion_matrix[i, :])
    scale_factor = data["classification_report"][str(i)]["support"] / row_sum
    confusion_matrix[i, :] *= scale_factor

confusion_matrix = np.round(confusion_matrix).astype(int)

print("使用FPR数据计算的混淆矩阵:")
print(confusion_matrix)
