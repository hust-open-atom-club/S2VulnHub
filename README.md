# S2VulnHub

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

## 快速开始
```
$ cd src

# 根据 data/user_cve/ 中的 json 文件自动生成 Dockerfile 到 data/user_dockerfile/
$ python cli.py reproduce CVE-2017-5980

# 检测 zziplib v0.13.62 是否受 CVE-2017-5980 影响
$ python cli.py scan CVE-2017-5980 -t v0.13.62
```

## 用法
```
$ python cli.py -h
usage: cli.py [-h] {reproduce,scan,info} ...

A CLI interface for vulhub

positional arguments:
  {reproduce,scan,info}
                        commands to run
    reproduce           generate Dockerfile for a vulnerability
    scan                scan if the app version is vulnerable
    info                get software build and depend info, print raw info if no option is specified

options:
  -h, --help            show this help message and exit
```