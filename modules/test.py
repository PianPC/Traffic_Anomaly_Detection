from models.dl.fsnet.fsnet_main_model import model as FSNetModel
import os
import tensorflow as tf
import numpy as np

# 1. 加载模型
model_service = FSNetModel('train_data_test', randseed=128, splitrate=0.6, max_len=200)

flow_data = [[66,-66,60,74,-60,-5894,-1514,-1514,-2889,-60,60,60]]




# 3. 进行预测
prediction = model_service.logit_online(flow_data)
pred_label = int(np.argmax(prediction))
print('---------------------------------------------------------------------------')
print(pred_label)        # predicted label
print(prediction)

