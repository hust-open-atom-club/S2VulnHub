# 快速开始

## 环境准备

```
# 建议使用 pipx 安装全局工具（pdm, black, isort, pre-commit等）
$ pipx install pdm

# 使用 pdm 在虚拟环境安装项目依赖
# https://pdm-project.org/zh-cn/latest/usage/venv/
$ pdm install

# 列出虚拟环境
$ pdm venv list
Virtualenvs created with this project:

*  in-project: /home/user/S2VulnHub/.venv

# 激活虚拟环境
$ eval $(pdm venv activate in-project)
```

## 用户态漏洞复现

```
(s2vulnhub-3.10)$ cd src

# 根据 data/user_cve/ 中的 json 文件自动生成 Dockerfile 到 data/user_dockerfile/
(s2vulnhub-3.10)$ python cli.py reproduce CVE-2017-5980

# 检测 zziplib v0.13.62 是否受 CVE-2017-5980 影响
(s2vulnhub-3.10)$ python cli.py scan CVE-2017-5980 -t v0.13.62
```

## 内核漏洞复现

### 本地 （以 syzbot 为例）

```
# Terminal 1

(s2vulnhub-3.10)$ python cli.py scan -k f3f3eef1d2100200e593
```

运行该命令会：
* 从 docker hub 拉取包含 bzImage 的基础镜像
* 启动容器，下载漏洞复现材料 (bzImage/.config, poc)
* 在容器中启动 qemu 虚拟机并运行 poc
* 观察到内核崩溃

### 使用 docker hub 镜像（以 CVE-2023-0179 为例）

```
$ docker pull jingyisong/kernel_bug_reproduce:cve-2023-0179

$ docker run --device=/dev/kvm -it cve-2023-0179:v1
```
