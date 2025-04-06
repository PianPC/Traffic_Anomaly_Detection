import os
import argparse
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def train_fsnet(timestamp):
    """训练FS-Net模型"""
    try:
        from models.dl.fsnet.fsnet_main_model import FSNet
        from models.dl.fsnet.preprocess import load_origin_data, preprocess

        # 设置数据目录
        data_dir = os.path.join('dataset', timestamp)

        # 加载并预处理数据
        logger.info("开始加载和预处理数据...")
        data = load_origin_data(data_dir)
        train_data, test_data = preprocess(data)

        # 初始化模型
        logger.info("初始化FS-Net模型...")
        model = FSNet()

        # 训练模型
        logger.info("开始训练模型...")
        model.train(train_data, test_data)

        logger.info("模型训练完成")
        return True

    except Exception as e:
        logger.error(f"训练FS-Net模型时出错: {str(e)}")
        return False

def train_df(timestamp):
    """训练DF模型"""
    try:
        from models.dl.df.df_main_model import DFModel

        # 设置数据目录
        data_dir = os.path.join('dataset', timestamp)

        # 初始化模型
        logger.info("初始化DF模型...")
        model = DFModel()

        # 训练模型
        logger.info("开始训练模型...")
        model.train(data_dir)

        logger.info("模型训练完成")
        return True

    except Exception as e:
        logger.error(f"训练DF模型时出错: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='训练模型')
    parser.add_argument('--timestamp', type=str, required=True, help='时间戳文件夹名称')
    parser.add_argument('--model', type=str, required=True, choices=['fsnet', 'df'],
                       help='模型类型：fsnet 或 df')
    args = parser.parse_args()

    logger.info(f"开始训练 {args.model} 模型...")
    logger.info(f"使用数据集: {args.timestamp}")

    if args.model == 'fsnet':
        success = train_fsnet(args.timestamp)
    elif args.model == 'df':
        success = train_df(args.timestamp)
    else:
        logger.error(f"不支持的模型类型: {args.model}")
        return

    if success:
        logger.info("模型训练成功完成")
    else:
        logger.error("模型训练失败")

if __name__ == '__main__':
    main()
