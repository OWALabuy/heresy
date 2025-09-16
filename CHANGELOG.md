# Changelog

## 0.1.0 (初始 Python 版)
- 新建 Python 项目骨架（src 布局），命令入口 heresy
- 实现订阅管理、节点列表/选择、配置生成、进程与系统代理控制（MVP）
- 解析与出站（MVP+）：
  - vless：支持 reality 参数与 ws/grpc 传输
  - vmess：标准 base64 JSON，含 alterId/tls/net/host/path/sni
  - trojan：支持 ws/grpc 相关 query；密码复用 uuid 字段
  - ss：支持 base64 与明文两种链接格式
  - hy2：仅解析（暂不生成出站）
- 文档：功能规格、数据模型、CLI 设计、重构路线图、使用说明、协议解析与出站生成
