# 如何贡献

## 软件格式

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
  + source: 表示这个软件的来源是压缩包
  + packages: 数组，包含多个软件包对象，每个对象包含两个字段：
    - url: 软件包的下载 URL
    - version: 软件包的版本
* build: 软件包编译命令

## 漏洞格式

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
  + poc: PoC 的下载 URL
  + guide: PoC 的执行命令，将被写入 trigger.sh

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
  + guide: PoC 的执行命令，将被写入 trigger.sh。默认为：编译 poc.c, scptovm poc, 执行 poc
  + bzImage: syzbot 提供的 bzImage URL
  + configfile: syzbot 提供的 configfile URL

## 代码结构

```
├── src
│   ├── cli.py              # 工具入口，根据用户输入的命令调用相应功能函数
│   ├── info_cmd.py         # 处理 info 命令
│   ├── repro_cmd.py        # 处理 reproduce 命令，生成 dockerfile
│   ├── os_gen.py           # 辅助完成 reproduce
│   ├── soft_gen.py         # 辅助完成 reproduce
│   ├── scan_cmd.py         # 处理 scan 命令，扫描软件的不同版本是否有漏洞
│   ├── kernel_scan_cmd.py  # 处理 kernel scan 命令，扫描 kernel 的不同版本是否有漏洞
│   ├── validate_cmd.py     # 处理 validate 命令，检查软件和漏洞文件格式是否合法
│   └── utils.py            # 设置 logger，添加用户到 docker 组
```

参考各个函数的 docstring 获得更多信息
