import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from scipy.interpolate import griddata

data = [
    # 格式: (x: 最小包数量, y: 最长检测时间, z: 准确率)
    (0.1, 3, 70.72),
    (0.1, 4, 68.35),
    (0.1, 5, 74.08),

    (0.3, 3, 63.00),
    (0.3, 4, 64.02),
    (0.3, 5, 61.68),

    (0.5, 2, 32.38),
    (0.5, 3, 73.05),
    (0.5, 4, 64.14),
    (0.5, 5, 66.32),
    (0.5, 6, 66.44),
    (0.5, 7, 53.36),
    (0.5, 8, 39.26),
    (0.5, 9, 60.31),

    (0.6, 2, 38.46),
    (0.6, 3, 65.18),
    (0.6, 4, 54.83),

    (1.0, 2, 53.02),
    (1.0, 3, 61.15),
    (1.0, 4, 63.38),
    (1.0, 5, 68.40),
    (1.0, 6, 65.51),
    (1.0, 7, 47.33),
    (1.0, 8, 48.02),

    (1.5, 2, 26.16),
    (1.5, 3, 54.11),
    (1.5, 4, 75.63),
    (1.5, 5, 70.59),
    (1.5, 6, 59.92),
    (1.5, 7, 52.08),
    (1.5, 8, 28.37),

    (1.7, 2, 32.43),
    (1.7, 3, 66.54),
    (1.7, 4, 60.99),

    (2.0, 2, 34.35),
    (2.0, 3, 68.71),
    (2.0, 4, 75.61),

    (2.5, 2, 33.68),
    (2.5, 3, 62.26),
    (2.5, 4, 71.97),
    (2.5, 5, 61.37),
    (2.5, 6, 56.79),
    (2.5, 7, 48.31),
    (2.5, 8, 47.13),

    (3.0, 4, 63.45),
    (3.0, 5, 69.22),
    (3.0, 6, 64.23),
    (3.0, 7, 53.22),
    (3.0, 8, 41.78),
    (3.0, 9, 63.59),

    (3.5, 4, 60.67),
    (3.5, 5, 60.53),
    (3.5, 6, 61.35),
    (3.5, 7, 49.11),
    (3.5, 8, 38.44),

    (3.9, 3, 55.09),

    (4.0, 3, 67.49),
    (4.0, 4, 71.26),
    (4.0, 5, 62.34),
    (4.0, 6, 49.90),
    (4.0, 7, 48.10)
]

# 解压数据
x = np.array([item[0] for item in data])
y = np.array([item[1] for item in data])
z = np.array([item[2] for item in data])

# 创建网格数据（用于曲面插值）
xi = np.linspace(min(x), max(x), 100)
yi = np.linspace(min(y), max(y), 100)
xi, yi = np.meshgrid(xi, yi)

# 插值生成平滑曲面
zi = griddata((x, y), z, (xi, yi), method='cubic')

# 设置中文字体（解决中文乱码）
plt.rcParams['font.sans-serif'] = ['SimHei']  # Windows系统
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# 创建3D图
fig = plt.figure(figsize=(12, 8))
ax = fig.add_subplot(111, projection='3d')

# 绘制曲面
surf = ax.plot_surface(
    xi, yi, zi,
    cmap='viridis',
    alpha=0.8,  # 透明度
    rstride=1, cstride=1,  # 曲面网格密度
    antialiased=True
)

# 添加散点图（标记实际数据点）
ax.scatter(x, y, z, c='red', s=10, label='实际数据点')

# 设置标签和标题
ax.set_xlabel('最长检测时间 (秒)', fontsize=12)
ax.set_ylabel('最小包数量', fontsize=12)
ax.set_zlabel('准确率 (%)', fontsize=12)
ax.set_title('模型准确率随参数变化趋势', fontsize=16, pad=20)

# 添加颜色条
fig.colorbar(surf, shrink=0.5, aspect=10, label='准确率 (%)')

# 调整视角
ax.view_init(elev=30, azim=45)  # 仰角30度，方位角45度

plt.tight_layout()
plt.show()


# import numpy as np
# import matplotlib.pyplot as plt
# from mpl_toolkits.mplot3d import Axes3D
# from scipy.interpolate import griddata



# # 解压数据
# x = np.array([item[0] for item in data])
# y = np.array([item[1] for item in data])
# z = np.array([item[2] for item in data])

# # 创建网格数据
# xi = np.linspace(min(x), max(x), 100)
# yi = np.linspace(min(y), max(y), 100)
# xi, yi = np.meshgrid(xi, yi)

# # 插值生成平滑曲面
# zi = griddata((x, y), z, (xi, yi), method='cubic')

# # 设置中文字体
# plt.rcParams['font.sans-serif'] = ['SimHei']
# plt.rcParams['axes.unicode_minus'] = False

# # 创建3D图
# fig = plt.figure(figsize=(12, 8))
# ax = fig.add_subplot(111, projection='3d')

# # 绘制曲面
# surf = ax.plot_surface(
#     xi, yi, zi,
#     cmap='viridis',
#     alpha=0.8,
#     rstride=1,
#     cstride=1,
#     antialiased=True
# )

# # 绘制散点图并启用拾取功能
# scatter = ax.scatter(x, y, z, c='red', s=20, label='实际数据点', picker=True)

# # 设置标签和标题
# ax.set_xlabel('最长检测时间 (秒)', fontsize=12)
# ax.set_ylabel('最小包数量', fontsize=12)
# ax.set_zlabel('准确率 (%)', fontsize=12)
# ax.set_title('模型准确率随参数变化趋势', fontsize=16, pad=20)

# # 添加颜色条
# fig.colorbar(surf, shrink=0.5, aspect=10, label='准确率 (%)')

# # 创建注释对象
# annot = ax.text2D(0.05, 0.95, "", transform=ax.transAxes,
#                  bbox=dict(boxstyle="round", fc="w", alpha=0.8),
#                  fontsize=10)
# annot.set_visible(False)

# # 点击事件处理函数
# def on_pick(event):
#     if event.artist != scatter:
#         return

#     ind = event.ind[0]
#     x_val, y_val, z_val = x[ind], y[ind], z[ind]

#     annot.set_text(f"最小包数量: {x_val:.1f}\n最长检测时间: {y_val}秒\n准确率: {z_val:.2f}%")
#     annot.set_visible(True)

#     # 更新注释位置
#     annot.xy = (0.05, 0.95)

#     fig.canvas.draw_idle()

# # 连接点击事件
# fig.canvas.mpl_connect('pick_event', on_pick)

# # 调整视角
# ax.view_init(elev=30, azim=45)

# plt.tight_layout()
# plt.show()
