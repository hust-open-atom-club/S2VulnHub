import os
import json
import re

# 定义要匹配的字段和对应的正则表达式
fields_to_match = {
    'poc': r'.*tag=ReproC.*',  # 请替换为实际的字段名和正则表达式
    'bzImage': r'.*bzImage-.*',  # 请替换为实际的字段名和正则表达式
    # 添加更多字段和正则表达式
}

def is_valid_json_file(file_path, fields_to_match):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        #print(data)
        # 检查每个字段是否符合正则表达式
        for field, pattern in fields_to_match.items():
            if field in data['trigger'] and not re.match(pattern, data['trigger'][field]):
                return False
        return True
    except (json.JSONDecodeError, KeyError):
        return False

def filter_json_files(directory, fields_to_match):
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            if not is_valid_json_file(file_path, fields_to_match):
                #x=input()
                print(f'Deleting file: {filename} because it does not match the required patterns.')
                os.remove(file_path)

# 调用函数，传入当前目录和字段匹配规则
filter_json_files('.', fields_to_match)