import getpass
import grp
import json
import logging
import os
import subprocess

from rich.logging import RichHandler

logging.basicConfig(level="NOTSET", format="%(message)s", handlers=[RichHandler()])
logger = logging.getLogger("s2vulhub")

def get_template(app_name:str)->dict:
    try:
        with open(f"../data/apps/{app_name}.json", "r") as f:
            schema = json.loads(f.read())
        return schema
    except Exception as e:
        logger.warning(e)
        exit(1)


def check_docker_permission():
    try:
        docker_gid = grp.getgrnam("docker").gr_gid
        user_groups = os.getgroups()
        if docker_gid in user_groups:
            return True
        else:
            return False
    except KeyError:
        return False


def add_user_to_docker_group():
    try:
        username = getpass.getuser()
        logger.info(f"尝试将用户 {username} 加入 docker 组...")
        subprocess.run(["sudo", "usermod", "-aG", "docker", username], check=True)
        logger.info(f"用户 {username} 已成功加入 docker 组。请重新登录以应用组更改。")
    except subprocess.CalledProcessError as e:
        logger.warning(f"添加用户到 docker 组失败: {e}")


if __name__ == "__main__":
    if not check_docker_permission():
        add_user_to_docker_group()
    else:
        logger.info("用户已在 docker 组")
