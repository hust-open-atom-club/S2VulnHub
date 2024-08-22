import os
import grp
import subprocess
import getpass
from logger import logger


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
