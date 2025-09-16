# 使用说明（MVP）

## 安装
```
pip install -e .
```

## 初始化
- 数据与配置目录：`~/.heresy/`
- 首次运行会自动创建数据库并初始化表

## 基本流程
```
heresy subscribe add --name 我的订阅 --url https://example.com/sub
heresy subscribe update --all
heresy node list
heresy node select 1
heresy config generate
heresy proxy start
heresy sys-proxy enable
```

## 诊断
```
heresy diag info
heresy proxy status
heresy sys-proxy status  # 未来版本
```

## 注意
- 目前节点链接解析为最小占位（MVP），后续将完善各协议字段
- Windows 系统代理需以当前用户运行；Linux 需 GNOME 环境或手动配置


