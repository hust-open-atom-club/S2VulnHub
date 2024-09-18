# S2VulnHub

- [S2VulnHub](#s2vulnhub)
  - [简介](#简介)
  - [用法](#用法)
  - [快速开始](#快速开始)
    - [环境准备](#环境准备)
    - [用户态漏洞复现](#用户态漏洞复现)
    - [内核漏洞复现](#内核漏洞复现)
      - [本地 （以 syzbot 为例）](#本地-以-syzbot-为例)
      - [使用 docker hub 镜像（以 CVE-2023-0179 为例）](#使用-docker-hub-镜像以-cve-2023-0179-为例)

## 简介

根据软件信息和漏洞信息自动化生成漏洞复现环境，可信地确定漏洞影响的软件版本范围。

data 目录存放漏洞复现相关的数据，src 目录存放源代码，scripts 目录存放脚本。

```
├── data
│   ├── apps                # 软件信息
│   ├── kernel_bug          # 内核态漏洞信息
│   ├── kernel_dockerfile   # 内核态漏洞 Dockerfile
│   ├── user_cve            # 用户态漏洞信息
│   └── user_dockerfile     # 用户态漏洞 Dockerfile
```

## 用法
```
$ python cli.py -h
usage: cli.py [-h] {reproduce,scan,info,validate} ...

A CLI interface for vulhub

positional arguments:
  {reproduce,scan,info,validate}
                        commands to run
    reproduce           generate Dockerfile for a vulnerability
    scan                scan if the app version is vulnerable
    info                get software build and depend info, print raw info if no option is specified
    validate            validate the vulnerability and software schema

options:
  -h, --help            show this help message and exit
```

## 快速开始

### 环境准备
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

### 用户态漏洞复现
```
(s2vulnhub-3.10)$ cd src

# 根据 data/user_cve/ 中的 json 文件自动生成 Dockerfile 到 data/user_dockerfile/
(s2vulnhub-3.10)$ python cli.py reproduce CVE-2017-5980

# 检测 zziplib v0.13.62 是否受 CVE-2017-5980 影响
(s2vulnhub-3.10)$ python cli.py scan CVE-2017-5980 -t v0.13.62
```

### 内核漏洞复现

#### 本地 （以 syzbot 为例）

``` 
# Terminal 1

(s2vulnhub-3.10)$ python cli.py reproduce -k f3f3eef1d2100200e593

(s2vulnhub-3.10)$ cd ../data/kernel_dockerfile
(s2vulnhub-3.10)$ docker build -f f3f3eef1d2100200e593 -t syzbot:f3 .

(s2vulnhub-3.10)$ docker run --device=/dev/kvm syzbot:f3
```

等待 qemu 虚拟机加载完成后启动 Terminal 2

```
# Terminal 2

(s2vulnhub-3.10)$ docker exec -it `docker ps -a --filter ancestor=syzbot:f3 -q | head -n 1` bash trigger.sh
```

此时可以在 Terminal 1 中观察到内核崩溃

#### 使用 docker hub 镜像（以 CVE-2023-0179 为例）

```
$ docker pull jingyisong/kernel_bug_reproduce:cve-2023-0179

$ docker run --device=/dev/kvm -it cve-2023-0179:v1
```