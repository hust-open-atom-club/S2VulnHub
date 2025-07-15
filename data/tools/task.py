import time
import os

def job(index,time):
    os.system("python3 generate_from_syzbot.py".format(index))
    print("执行任务 "+str(time))

# 记录程序开始运行的时间
start_time = time.time()

# 定义任务执行的时间点
time_to_run = [180, 600, 1200,2400,3600,6000,12000,18000,30000,50000,86400,172800]  # 单位为秒
index=0
x=0
while True:
    current_time = time.time() - start_time
    if current_time>index*1800 :
        job(index,current_time)
        index+=1
        if index>=50 :
            break

    time.sleep(1)  # 每秒检查一次是否到达执行时间
