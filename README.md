# GitHub Secret Scanner Pro

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Version](https://img.shields.io/badge/version-v2.2--smart--cache-orange.svg)
![Performance](https://img.shields.io/badge/performance-100x+-brightgreen.svg)

> 企业级 GitHub 密钥扫描与验证系统 - 已统一入口

GitHub Secret Scanner Pro 是一款高性能的自动化工具，专为安全研究人员和红队设计。
它利用 GitHub API 实时扫描代码库中的敏感密钥，并使用高并发异步架构进行深度有效性验证。

> ⚠️ **免责声明**: 本项目仅用于授权的安全测试和教育目的。严禁用于非法扫描或利用他人凭证。使用者需自行承担所有法律责任。

## 快速开始

`ash
# 克隆仓库
git clone https://github.com/Coft0xc/Github-API-scan.git
cd Github-API-scan

# 安装依赖
pip install -r requirements.txt

# 配置 GitHub Token
set GITHUB_TOKENS="ghp_xxxxxxxxxxxx,ghp_yyyyyyyyyyyy"
# 或创建 config_local.py 文件

# 启动扫描（统一入口，默认启用 v2.2 全部特性）
python main.py
`

### 常用命令

| 命令 | 说明 |
|------|------|
| python main.py | 启动扫描（v2.2 智能缓存） |
| python main.py --no-cache | 禁用缓存（回退 v2.1 行为） |
| python main.py --no-monitor | 禁用性能监控 |
| python main.py --monitor | 实时监控 + 推送模式 |
| python main.py --stats | 显示数据库统计 |
| python main.py --export valid.txt | 导出有效 Key |
| python main.py --export-csv keys.csv | 导出 CSV |
| python main.py --all-sources | 启用所有扫描源 |
| python benchmark.py | 性能测试 |

## 核心特性

### 统一入口（v2.2 + v2.1 + v2.0）

所有版本现已合并为单一的 python main.py 入口：

- **智能缓存 (v2.2)** — 3层缓存架构，L1验证结果缓存 + L2域名健康度 + L3指纹去重，命中率 30-50%
- **批量验证 (v2.2)** — 按域名分组验证，网络请求减少 40-60%，DNS 查询减少 70-80%
- **域名健康追踪 (v2.2)** — 自动识别死域名并跳过，避免无效验证
- **LRU缓存淘汰 (v2.2)** — 智能淘汰最少使用条目，内存使用可控
- **自动缓存清理 (v2.2)** — 定期清理过期缓存，保持系统高效
- **HTTP连接池 (v2.1)** — 按域名复用连接，减少 TCP/TLS 握手开销 70-80%
- **智能重试机制 (v2.1)** — 指数退避 + 错误分类，成功率提升 15-25%
- **动态队列管理 (v2.1)** — 根据内存压力自动调整，内存使用降低 30-50%
- **性能监控系统 (v2.1)** — P50/P95/P99 延迟统计，实时吞吐量追踪
- **异步数据库 (v2.0)** — 使用 aiosqlite 实现批量写入，性能提升 **100-430倍**
- **加密导出 (v2.0)** — 使用 Fernet 对称加密保护敏感数据
- **配置外部化 (v2.0)** — config.yaml 支持，无需修改代码即可调参
- **配置验证 (v2.0)** — 启动时自动检查配置完整性

> 旧的入口文件（main_v2.2.py、main_v2.1.py、main_optimized.py）仍保留做向后兼容，但会打印弃用警告。请尽快迁移到 python main.py。

### 性能对比

| 测试规模 | 原版耗时 | 优化版耗时 | 加速比 |
|---------|---------|-----------|--------|
| 100条记录 | 10.38秒 | 0.10秒 | **108x** |
| 500条记录 | 52.08秒 | 0.16秒 | **320x** |
| 1000条记录 | 103.29秒 | 0.24秒 | **430x** |

### 多源扫描
- **GitHub Code Search** - 精准搜索泄露的密钥
- **GitHub Gist** - 扫描公开 Gist
- **GitLab** - 支持 GitLab 公开仓库
- **Pastebin** - 实时监控粘贴板
- **SearchCode** - 跨平台代码搜索
- **GitHub Events API** - 实时监控新提交
- **Sourcegraph** - 补充扫描源

### 多平台验证
支持验证 **12+ AI 平台** 的 API Key：

| 平台 | 验证方式 | 深度探测 |
|------|----------|----------|
| OpenAI | chat/completions | GPT-4 权限、余额、RPM |
| Anthropic | messages | Claude-3 模型识别 |
| Google Gemini | generateContent | 配额检测 |
| Azure OpenAI | 上下文感知 | Endpoint 自动提取 |
| Groq | chat/completions | 模型列表 |
| DeepSeek | chat/completions | 余额检测 |
| Mistral | chat/completions | 模型权限 |
| Cohere | chat | API 状态 |
| Together | chat/completions | 模型列表 |
| HuggingFace | whoami | 账号验证 |
| Replicate | account | 账号状态 |
| Perplexity | chat/completions | 在线模型 |

### 实时推送通知
发现可用 Key 时立即推送：
- **微信** - WxPusher (免费无限制)
- **微信/QQ** - PushPlus
- **Telegram** - Bot 推送
- **钉钉** - 机器人 Webhook
- **声音** - 本地蜂鸣提醒
- **文件** - 自动记录到桌面

### 高性能架构
- **异步并发** - asyncio + aiohttp，200+ 并发验证
- **智能断路器** - 自动熔断不稳定节点
- **Token 轮询** - 突破 GitHub API 限制
- **断点续传** - SQLite 持久化存储

## 配置

### GitHub Token 配置

`python
# config_local.py
GITHUB_TOKENS = [
    "ghp_xxxxxxxxxxxx",
    "ghp_yyyyyyyyyyyy",
]
`

或使用环境变量：
`ash
set GITHUB_TOKENS="ghp_xxx,ghp_yyy"
`

### 推送通知配置

编辑 
otifier.py 配置推送：

`python
notifier = Notifier(
    wxpusher_token="YOUR_TOKEN",      # WxPusher
    wxpusher_uid="YOUR_UID",
    # telegram_token="BOT_TOKEN",     # Telegram
    # telegram_chat_id="CHAT_ID",
    # dingtalk_webhook="WEBHOOK_URL", # 钉钉
)
`

## 文档索引

- **[QUICKSTART.md](QUICKSTART.md)** - 5分钟快速上手指南
- **[OPTIMIZATION.md](OPTIMIZATION.md)** - 优化技术细节和架构说明
- **[OPTIMIZATION_V2.1.md](OPTIMIZATION_V2.1.md)** - v2.1 优化报告（连接池、智能重试、动态队列）
- **[OPTIMIZATION_V2.2.md](OPTIMIZATION_V2.2.md)** - v2.2 优化报告（智能缓存、批量验证）
- **[MIGRATION.md](MIGRATION.md)** - 从原版迁移到优化版的完整指南

## 配置调优

编辑 config.yaml 调整性能参数：

`yaml
# 高性能配置
validator:
  max_concurrency: 200
  num_workers: 4

database:
  batch_size: 100
  flush_interval: 2.0

# 低资源配置
validator:
  max_concurrency: 50
  num_workers: 1

database:
  batch_size: 20
  flush_interval: 10.0
`

## 免责声明

本项目仅用于**授权的安全测试和教育目的**。严禁用于非法扫描或利用他人凭证。

使用者需自行承担所有法律责任。作者不对任何滥用行为负责。

## 许可

[MIT License](LICENSE)

---

**Made with ❤️ for Security Researchers**
