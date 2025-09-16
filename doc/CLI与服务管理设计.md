# CLI 与服务管理设计

## 1. 命令结构
```
heresy
  subscribe
    add --name NAME --url URL
    list
    update [ID|--all]
    edit ID [--name NAME] [--url URL]
    delete ID
  node
    list [--subscribe ID]
    select ID
    ping ID [--count 3] [--timeout 1000]
    import LINK           # 选做
    export ID             # 选做
  config
    generate              # 使用当前节点
    path
  proxy
    start [--xray PATH] [--hysteria PATH]
    stop
    status
  sys-proxy
    enable [--port 10809] [--socks 10808]
    disable
    status
  diag
    info
```

## 2. 组件职责
- subscribe 模块：下载、解码、解析、事务入库；错误统计与日志
- node 模块：筛选、选择、测速；导入导出
- config 模块：生成 xray_config.json；静态片段拼装与协议适配
- proxy 模块：启动/停止 Xray/Hysteria2；捕获日志与状态
- sys-proxy 模块：设置/清除系统代理；能力检测与回退
- diag 模块：统一输出状态快照

## 3. 进程与安全
- Windows：`subprocess.CREATE_NO_WINDOW` 启动；停止使用 `taskkill /IM xray.exe` 前先查询 PID
- Linux：后台启动（`Popen`）；停止前用 `pidfile`/`pgrep` 精确匹配
- 禁用拼接命令字符串：使用参数数组；校验路径与参数白名单
- hy2：在当前节点协议为 `hy2` 时，先生成 `~/.heresy/hy2_config.yaml` 并联动启动 hysteria2；Xray 通过本地 socks(127.0.0.1:10810) 分流至 hy2；停止时一并清理

## 4. 系统代理策略
- Windows：优先使用 `winreg` 设置 `ProxyEnable` 与 `ProxyServer`；可选 `InternetSetOption`（pywin32）
- Linux：优先 `gsettings`；若不可用，提示环境变量方案（用户 shell 级）
- 状态查询：读取当前系统配置并与应用配置对比

## 5. 配置生成细节
- inbounds：
  - http-in: 127.0.0.1:10809
  - socks-in: 127.0.0.1:10808
- outbounds：
  - proxy（当前节点协议适配）
  - direct / block / dns-out
- routing：
  - 直连 `geosite:cn`、`geoip:cn/private`
  - udp 53 → dns-out

## 6. 错误处理
- 订阅更新：网络错误/解码失败/行解析失败分别计数并详细日志
- 启停代理：二进制不存在/权限不足/配置无效要提示与建议
- 系统代理：权限不足/缺少组件（如 gsettings）需降级说明

## 7. 输出规范
- 采用 `rich` 表格与颜色输出
- `--json` 开关：以 JSON 输出重要命令结果（便于脚本化）

## 8. 日志
- 默认输出到控制台；可选写入 `~/.heresy/logs/heresy.log`
- 重要操作（更新、生成、启停、系统代理）写入 INFO；异常写入 ERROR


