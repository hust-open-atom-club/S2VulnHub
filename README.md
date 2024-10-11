# S2VulnHub

## 简介

根据软件信息和漏洞信息自动化生成漏洞复现环境，可信地确定漏洞影响的软件版本范围。

data 目录存放漏洞复现相关的数据，src 目录存放源代码，scripts 目录存放脚本，docs 目录存放文档。

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
