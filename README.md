# HERESY（Python 版）

跨平台 Xray-Core 管理 CLI，支持：订阅管理、节点解析入库、配置生成、进程控制、系统代理开关。

## 安装
```
pip install -e .
```

## 使用
```
heresy --help
```

常用命令：
```
heresy subscribe add --name NAME --url URL
heresy subscribe update --all
heresy node list
heresy node select ID
heresy config generate
heresy proxy start
heresy sys-proxy enable
```

数据与配置目录：`~/.heresy/`。
