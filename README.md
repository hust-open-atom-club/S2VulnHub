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
  - [如何贡献](#如何贡献)
    - [代码结构](#代码结构)

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

(s2vulnhub-3.10)$ python cli.py scan -k f3f3eef1d2100200e593
```
运行该命令会：
* 从 docker hub 拉取包含 bzImage 的基础镜像
* 启动容器，下载漏洞复现材料 (bzImage/.config, poc)
* 在容器中启动 qemu 虚拟机并运行 poc
* 观察到内核崩溃

#### 使用 docker hub 镜像（以 CVE-2023-0179 为例）

```
$ docker pull jingyisong/kernel_bug_reproduce:cve-2023-0179

$ docker run --device=/dev/kvm -it cve-2023-0179:v1
```


## 如何贡献
### 代码结构
```
├── src
│   ├── cli.py            # 工具入口，根据用户输入的命令调用相应功能函数
│   ├── info_cmd.py       # 处理 info 命令
│   ├── os_gen.py         # 被 repro_cmd.py 调用
│   ├── repro_cmd.py      # 处理 reproduce 命令，生成 dockerfile
│   ├── scan_cmd.py       # 处理 scan 命令，扫描软件的不同版本是否有漏洞
│   ├── soft_gen.py       # 被 repro_cmd.py 调用
│   ├── utils.py          # 设置 logger，添加用户到 docker 组
│   └── validate_cmd.py   # 处理 validate 命令，检查软件和漏洞文件格式是否合法
```
参考各个函数的 docstring 获得更多信息