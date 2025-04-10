import tensorflow as tf

# 指定模型目录
model_dir = './data/fsnet_train_data_model/log'
flow_data = './dataset/train_data/test.json'

# 加载计算图和权重
sess = tf.Session()
saver = tf.train.import_meta_graph(f'{model_dir}/model.ckpt-10000.meta')
saver.restore(sess, tf.train.latest_checkpoint(model_dir))

# 获取输入/输出张量
graph = tf.get_default_graph()
input_tensor = graph.get_tensor_by_name('IteratorGetNext:2')  # 根据实际名称修改
output_tensor = graph.get_tensor_by_name('classify/dense/BiasAdd:0')  # 根据实际名称修改

# 执行预测
predictions = sess.run(output_tensor, feed_dict={input_tensor: flow_data})
