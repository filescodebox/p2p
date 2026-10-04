# FilesCodeBox P2P

[![CI](https://github.com/filescodebox/p2p/actions/workflows/ci.yml/badge.svg)](https://github.com/filescodebox/p2p/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/filescodebox/p2p?label=release)](https://github.com/filescodebox/p2p/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)

FilesCodeBox 生态的 **P2P 联邦注册中心**：让任意多个 FilesCodeBox 节点（server / fnos / desktop）互相发现，口令分享跨站可达——文件始终从源节点直出，注册中心不落盘、不见明文。

**The federated registry for FilesCodeBox**: nodes register, passcodes resolve across sites, files flow directly from the source node — the registry stores no files and never sees plaintext passcodes.

## 它解决什么

| 能力 | 说明 | 状态 |
|---|---|---|
| 节点注册与心跳 | Ed25519 签名租约（node_id 即公钥），TTL 到期自动清扫 | ✅ v0.1 |
| 口令联邦路由 | `SHA-256(口令) → 源节点`，取件方直连源节点、源节点本地校验口令，零跨节点信任 | ✅ v0.1 |
| 设备直传 | 无公网设备经 WS 信令 + PAKE + 打洞直连，失败走端到端加密中继 | 🚧 M3 |

非目标：内容 DHT 去中心化、离线传输、文件中转存储。

## 快速开始

```bash
docker run -d --name fcb-p2p -p 12346:12346 \
  -e FCB_P2P_ADMIN_PASSWORD=$(openssl rand -hex 16) \
  ghcr.io/filescodebox/p2p:latest
```

源码构建：

```bash
make build && ./bin/p2pd            # 默认端口 12346
make smoke                          # 冒烟:注册/公告/解析/撤销/注销全流程
```

## 配置

优先级：`FCB_P2P_*` 环境变量 > 配置文件（`--config` / `CONFIG_PATH`）> 内置默认。完整样例见 [configs/config.yaml](./configs/config.yaml)。

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `FCB_P2P_SERVER_PORT` | `12346` | HTTP/信令端口 |
| `FCB_P2P_SERVER_BEHIND_PROXY` | `false` | 反代部署置 true（取 X-Forwarded-For 参与限流） |
| `FCB_P2P_REGISTRATION_MODE` | `open` | `open` 开放注册 / `token` 邀请制 |
| `FCB_P2P_REGISTRATION_TOKEN` | — | token 模式的共享注册密钥 |
| `FCB_P2P_ADMIN_PASSWORD` | — | 留空 = 管理 API 整体禁用；生产必须注入 |
| `FCB_P2P_ANNOUNCE_MAX_PER_NODE` | `1000` | 单节点公告配额 |
| `FCB_P2P_ANNOUNCE_MAX_TTL` | `168h` | 公告最大存活 |
| `FCB_P2P_LOG_LEVEL` | `info` | debug / info / warn / error |

## API（v1）

| 方法 路径 | 说明 |
|---|---|
| `POST /v1/nodes/register` | 注册/续租（`/v1/nodes/heartbeat` 同语义别名） |
| `DELETE /v1/nodes/{id}` | 注销并级联撤公告 |
| `GET /v1/nodes/{id}` | 节点公开信息 |
| `POST /v1/announces` | 宣告 `code_hash → 本节点`（先到先得，冲突 409） |
| `DELETE /v1/announces/{hash}` | 撤销（仅宣告节点） |
| `GET /v1/resolve/{hash}` | 解析 → `{node_id, url, ...}`；未接入 404 |
| `GET /health` · `GET /metrics` | 健康检查（显式 GET）/ Prometheus 指标 |
| `GET/DELETE /v1/admin/*` | 统计/列表/强制下线（Bearer 管理口令） |

### 签名约定

所有写操作带 Ed25519 签名（base64 std），负载为字段按序 `"\n"` 连接，签名公钥即 `node_id`：

```
注册/心跳:   node_id | url | name | version | caps(逗号连接) | ttl_seconds | nonce | ts
公告:        node_id | code_hash | expires_at | size_hint | ts
注销节点:    node_id | ts
撤销公告:    node_id | code_hash | ts
```

`ts` 为 unix 秒，允许 ±300s 偏移。参考实现见 [scripts/smokegen](./scripts/smokegen)（生态接入后由 core `federation` 域服务封装）。

## 安全模型

- **注册中心不接触明文口令**：公告只存 `SHA-256(口令)`；解析方须持有口令才能计算哈希查询。
- **离线枚举防线在宣布侧**：生态客户端（core）只对熵 ≥40bit 的口令发联邦公告，短数字取件码不出站；解析接口按 IP 严格限流。
- **身份不可冒名**：node_id 即 Ed25519 公钥，全部写操作验签；管理端可强制下线作恶节点。
- **限流分层**：读/写/管理路径独立令牌桶，超限 429。
- **中继（M3）默认关闭**，开启后仅 PAKE 会话凭据放行且限带宽——不存在可被滥用的开放代理。

## 生态导航

| 仓库 | 角色 |
|---|---|
| [filescodebox](https://github.com/filescodebox/filescodebox) | 装配 hub：go.work + 文档 + 部署清单 |
| [contracts](https://github.com/filescodebox/contracts) · [core](https://github.com/filescodebox/core) | 契约层 · 业务核心库（`federation` 域服务对接本服务） |
| [server](https://github.com/filescodebox/server) · [frontend](https://github.com/filescodebox/frontend) | 独立部署壳 · Web 前端 |
| [fnos](https://github.com/filescodebox/fnos) · [desktop](https://github.com/filescodebox/desktop) | 飞牛 fnOS 适配 · 桌面客户端（M3 直传对等端） |
| [charts](https://github.com/filescodebox/charts) | Kubernetes Helm Chart |

依赖方向：`server / fnos / frontend / p2p → core → contracts`；p2p 为叶子仓，零生态依赖（CI 守卫强制）。

## License

[Apache-2.0](./LICENSE) — `Copyright 2026 FilesCodeBox`。本项目为独立实现，未移植 vastsa/FileCodeBox（LGPL-3.0）或 schollz/croc（MIT，仅以依赖方式参考其 PAKE 思路）的源码。
