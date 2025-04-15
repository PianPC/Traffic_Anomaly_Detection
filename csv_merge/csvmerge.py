import pandas as pd
import os
from datetime import datetime

def merge_csv_files(file_paths, output_file, how='concat', on=None):
    """
    合并多个CSV文件

    参数:
        file_paths: list - 要合并的CSV文件路径列表
        output_file: str - 合并后的输出文件路径
        how: str - 合并方式 ('concat'|'merge')
                  'concat': 简单纵向拼接（默认）
                  'merge': 根据指定列横向合并
        on: str/list - 横向合并时的键列（仅how='merge'时有效）
    """
    # 验证输入文件
    for file in file_paths:
        if not os.path.exists(file):
            raise FileNotFoundError(f"文件不存在: {file}")

    # 读取所有CSV文件
    dfs = []
    for i, file in enumerate(file_paths):
        try:
            df = pd.read_csv(file)
            # 添加来源标记（可选）
            df['_source_file'] = os.path.basename(file)
            dfs.append(df)
            print(f"已加载 {file} (行数: {len(df)}, 列数: {len(df.columns)})")
        except Exception as e:
            print(f"读取 {file} 失败: {str(e)}")
            continue

    if not dfs:
        raise ValueError("没有有效的CSV文件可合并")

    # 执行合并
    if how == 'concat':
        # 纵向拼接
        merged_df = pd.concat(dfs, axis=0, ignore_index=True)
        print(f"\n纵向拼接完成，总行数: {len(merged_df)}")
    elif how == 'merge':
        # 横向合并
        if not on:
            # 尝试自动查找共同列
            common_cols = set(dfs[0].columns)
            for df in dfs[1:]:
                common_cols.intersection_update(df.columns)
            if not common_cols:
                raise ValueError("没有找到共同列用于合并")
            on = list(common_cols)[0]  # 默认使用第一个共同列
            print(f"自动选择合并列: {on}")

        merged_df = dfs[0]
        for df in dfs[1:]:
            merged_df = pd.merge(merged_df, df, how='outer', on=on)
        print(f"\n横向合并完成，总行数: {len(merged_df)}")
    else:
        raise ValueError("不支持的合并方式，请选择 'concat' 或 'merge'")

    # 保存结果
    try:
        # 添加合并时间戳
        merged_df['_merge_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # 写入CSV（根据文件大小自动选择最佳方式）
        if len(merged_df) > 1_000_000:  # 大数据集使用更高效的方式
            merged_df.to_csv(output_file, index=False, chunksize=100_000)
        else:
            merged_df.to_csv(output_file, index=False)

        print(f"\n合并结果已保存到: {output_file}")
        print(f"总行数: {len(merged_df)}")
        print(f"总列数: {len(merged_df.columns)}")
        print("列名:", merged_df.columns.tolist())

        return output_file
    except Exception as e:
        print(f"保存合并文件失败: {str(e)}")
        raise

if __name__ == "__main__":
    # 示例用法
    csv_files = [
        # "csv_merge/Friday-WorkingHours-Morning.pcap_ISCX.csv",
        # "csv_merge/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        # "csv_merge/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "csv_merge/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "csv_merge/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    ]

    # output_path = "output/Friday-WorkingHours.csv"
    output_path = "output/Thursday-WorkingHours.csv"

    # 简单纵向拼接（默认）
    merge_csv_files(csv_files, output_path)

    # 如果需要横向合并（基于共同列）
    # merge_csv_files(csv_files, output_path, how='merge', on='id')
