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
    - [软件格式](#软件格式)
    - [漏洞格式](#漏洞格式)
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
### 软件格式
包含内容：软件名称 (name)，软件依赖 (environment)，软件源 (software) 和编译命令 (build)。

以 [python.json](/data/apps/python.json) 为例：
```
"software": {
    "source": "tarball",
    "packages": [
        {
            "url": "https://github.com/mudongliang/source-packages/raw/master/CVE-2014-4616/Python-2.7.1.tgz",
            "version": "2.7.1"
        },
        {
            "url": "https://github.com/mudongliang/source-packages/raw/master/CVE-2014-7185/Python-2.7.6.tgz",
            "version": "2.7.6"
        }
    ]
},
"build": "./configure\nmake -j"
```
* software
  * source: 表示这个软件的来源是压缩包
  * packages: 数组，包含多个软件包对象，每个对象包含两个字段：
    * url: 软件包的下载 URL
    * version: 软件包的版本
* build: 软件包编译命令

### 漏洞格式

用户态漏洞以 [CVE-2014-4616.json](/data/user_cve/CVE-2014-4616.json) 为例：
```
"id": "CVE-2014-4616",
"category": "python",
"version": "2.7.1",
"trigger": {
    "poc": "https://github.com/mudongliang/LinuxFlaw/raw/master/CVE-2014-4616/poc.py",
    "guide": "./python poc.py"
}
```
* category: 软件名称
* version: 软件版本
* trigger: 漏洞触发信息
  * poc: PoC 的下载 URL
  * guide: PoC 的执行命令，将被写入 trigger.sh

syzbot 漏洞以 [f3f3eef1d2100200e593.json](/data/kernel_bug/f3f3eef1d2100200e593.json) 为例：
```
"id": "f3f3eef1d2100200e593",
"trigger": {
    "poc": "https://syzkaller.appspot.com/text?tag=ReproC&x=128b1d53180000",
    "bzImage": "https://storage.googleapis.com/syzbot-assets/c02d1542e886/bzImage-7b4f2bc9.xz",
    "configfile": "https://syzkaller.appspot.com/text?tag=KernelConfig&x=ae644165a243bf62"
}
```
* id: https://syzkaller.appspot.com/bug?extid=07762f019fd03d01f04c
* trigger: 漏洞触发信息
  * guide: PoC 的执行命令，将被写入 trigger.sh。默认为：编译 poc.c, scptovm poc, 执行 poc
  * bzImage: syzbot 提供的 bzImage URL
  * configfile: syzbot 提供的 configfile URL

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