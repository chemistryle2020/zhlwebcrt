# zhlwebcrt — 网络设备智能运维平台

面向网络运维/技术支持工程师的一体化 Web 运维平台：在浏览器里完成**设备台账管理、
批量配置采集、配置变更对比、全文检索、实时监控告警、SNMP 深度巡检、在线 Web 终端排障**，
把"逐台登录设备敲命令"的传统运维方式升级为自动化、可审计、可视化的运维体系。

内置全局**采集/配置双模式安全开关**：采集模式下服务端强制只读命令白名单，
违规命令根本无法到达设备——从机制上杜绝巡检误操作打挂生产设备的风险。

## 功能特性

### 📊 监控大盘
- 设备在线状态、TCP 时延、CPU/内存、板卡温度、接口 up/down、整机流量一屏总览
- **SNMP 优先、SSH 解析兜底**的双通道采集：有 SNMP 走 SNMP，没配 SNMP 自动降级为 SSH 只读命令解析
- 按机房/区域分组的文件夹视图，各区在线/离线数量一目了然
- 多级告警（严重/警告/恢复）+ 浏览器声音提醒 + 告警确认闭环，历史趋势曲线（Chart.js）
- 支持 SNMP v1 / v2c / **v3（authPriv, MD5/SHA + DES/AES）**

### 🔍 SNMP 深度巡检（中兴 ZXR10 私有 MIB 适配）
- 光模块诊断：收发光功率(dBm)、温度、电压、偏置电流，支持有效性标志位
- 硬件状态：风扇转速、电源功率（容量/已用）、板卡温度及设备侧告警门限判断
- 处理中兴私有索引编码（接口名字符串索引、机架/槽位/单元复合索引）
- 巡检结果一键导出 **Excel 报告**

### 📥 批量配置采集
- 多线程并发采集引擎（并发度可调），支持命令预设模板、按分组/单设备下发
- APScheduler 定时任务：crontab 风格周期自动采集
- 采集结果自动**版本对比（diff 高亮变更行）**，可配置忽略模式（时间戳等噪声行）
- 基于 SQLite FTS5 的全文检索：十万级历史采集输出秒级搜索
- Excel 模板批量导入/导出设备台账

### 💻 Web 在线终端
- WebSocket + Paramiko + xterm.js 实现浏览器直连设备的实时交互终端
- 屏幕追踪式过滤：Tab 补全、方向键、历史命令等交互体验与直连一致

### 🔐 安全设计（生产环境红线）
- **采集/配置双模式**：采集模式下服务端强制只读命令白名单（`show`/`display`/`dir` 等，可自定义），
  违规命令在回车前被拦截并自动 Ctrl+C 清除，**永远没有执行机会**
- 所有经终端和任务执行的命令**全量审计日志**（Web 页签 + 落盘文件）
- 设备凭据 Fernet 对称加密存储，密钥独立文件隔离（`data/secret.key`，不入库、不进版本库）
- SQLite 数据、密钥、采集输出统一隔离在 `data/` 目录

### 🏢 多厂商支持
华为 / H3C / 中兴（ZTE ZXR10）/ 思科 / 锐捷 / Linux 服务器，
基于 Netmiko 驱动体系，新增厂商只需配置解析规则。

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | FastAPI + Uvicorn，SQLAlchemy + SQLite（WAL），APScheduler |
| 网络 | Netmiko / Paramiko（SSH、Telnet），pysnmp（SNMP v1/v2c/v3） |
| 前端 | Vue 3 + Element Plus + Chart.js + xterm.js（单页暗色运维风） |
| 数据处理 | openpyxl（Excel 导入导出），pyte（终端屏幕模拟），FTS5（全文检索） |

## 快速开始

**Linux / WSL：**

```bash
git clone https://github.com/chemistryle2020/zhlwebcrt.git
cd zhlwebcrt
./start.sh          # 首次运行自动建虚拟环境并安装依赖
```

**Windows：** 安装 Python 3.10+ 后双击 `start.bat`

浏览器打开 http://127.0.0.1:18080

### 使用流程

1. **凭据管理**：新增设备登录凭据（密码加密存储）；如需 SNMP 监控，再建 SNMP 模板
   （v2c 填只读 community，v3 填用户 + 认证/加密密钥）
2. **设备管理**：下载 Excel 模板 → 填设备清单 → 导入；设备类型按厂商选择
   （`huawei` / `hp_comware` / `zte_zxros` / `cisco_ios` / `ruijie_os` / `linux`）
3. **采集任务**：勾选设备 → 填命令（或用快捷模板）→ 开始采集 → 实时进度 → 结果对比/检索/打包下载
4. **监控大盘**：绑定 SNMP 模板后自动进入周期监控，告警声音提醒

## 项目结构

```
app/
├── main.py            # FastAPI 入口、APScheduler 挂载
├── config.py          # 配置管理、密钥加载/生成
├── models.py          # SQLAlchemy 数据模型
├── api/               # RESTful API：设备/凭据/任务/监控/SNMP/审计/检索…
├── core/
│   ├── collector.py   # 批量采集引擎（线程池并发）
│   ├── terminal.py    # WebSocket 终端 + 屏幕追踪命令过滤
│   ├── cmdfilter.py   # 只读命令白名单（采集模式铁律）
│   ├── monitor.py     # 监控调度：SNMP 优先 + SSH 兜底、告警判定
│   ├── snmp.py        # SNMP 封装 + 中兴私有 MIB 采集
│   ├── diffing.py     # 配置版本对比
│   └── scheduler.py   # 定时任务
└── static/index.html  # 前端单页应用
```

## License

MIT
