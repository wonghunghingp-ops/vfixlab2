# Node2Shell — CVE-2026-111497：Node.js Brotli 解码器越界写远程代码执行（FixLab 已验证）

[English](README.md) | [FixLab 官网](https://vfixlab.com)

## 概述

Node2Shell 是 Node.js 内置 Brotli 解码器中的严重远程代码执行（RCE）漏洞，编号 CVE-2026-111497，CVSS 9.2。畸形 Brotli 流先声明单一块类型、随后非法切换块，脆弱解码器把格式错误误读为“需要更多输入”，继续向 8 字节内部缓冲追加写入，破坏解码器状态。应用一旦用 `node:zlib` 解压攻击者可控的 Brotli 数据，这处破坏就可能被推向任意命令执行，以 Node 进程用户身份运行——在我们的实验里是 `uid=1000(node)`。

**FixLab 已在隔离靶场端到端验证过**：Node 24.22.0 上 RCE 跑通，修复版 Node 24.22.1 上被干净挡住。如果你跑的是受影响的 Node 分支，升级到该分支的修复版本（22.23.4、24.22.1 或 26.12.1），这就是修复方法。

## 速查表

| 项目 | 内容 |
|---|---|
| 漏洞 | Node2Shell — Brotli 解码器越界写 → RCE |
| CVE | CVE-2026-111497 |
| CVSS | 9.2（严重） |
| 受影响 Node.js | 22.x < 22.23.4、24.x < 24.22.1、26.x < 26.12.1 |
| 停止维护分支 | 20.x 及其他已停止维护分支没有修复——升级到受支持分支 |
| 来源中列出的受影响 Brotli 版本 | 1.0.3–1.0.9、1.1.0、1.2.0 |
| 触发前提 | 应用必须用 `node:zlib` 解压攻击者可控的 Brotli 数据 |
| 上游修复 | Brotli 增加 `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`（-17）：非法切换直接报格式错；修复版 Node 对同一输入返回 `ERR__ERROR_FORMAT_BLOCK_SWITCH`，服务保持存活 |
| FixLab 实验确认受影响 | Node 24.22.0（Express 5.3.0 应用，仅回环） |
| 验证过的修复版本 | Node 24.22.1 |
| FixLab 验证结论 | 24.22.0 上 RCE 验证通过；24.22.1 上被阻断（见下文） |

## 受影响与修复版本

- **受影响：** Node.js 22.x（22.23.4 之前）、24.x（24.22.1 之前）、26.x（26.12.1 之前）。
- **修复版本：** 22.23.4、24.22.1、26.12.1（用你所在分支的修复版本）。
- **已停止维护分支（例如 20.x）：** 不提供修复——升级到受支持分支。
- 只看版本号还不够：只有应用会解压攻击者可控的 Brotli 数据时，这个漏洞才可达。跑着脆弱版 Node、但没有任何此类路径的主机，本身不会因此暴露端点——但只要有应用在修复前 Node 上解压不受信任的 Brotli 输入，就是暴露的。

## 原理

攻击链大体是：

1. 应用用 `node:zlib` 解压攻击者可控的 Brotli 数据。我们的实验里是一个接受 `Content-Encoding: br` 请求体的 Express 应用；同类触发点还包括 `fetch()` 拉取恶意响应，以及直接对不受信任输入调 `zlib`。
2. 畸形 Brotli 流先声明单一块类型，随后非法切换块。
3. 脆弱解码器把格式错误误读为“需要更多输入”，继续向 8 字节内部缓冲追加写入，破坏解码器状态。
4. 破坏被推向 ROP 链，劫持执行到攻击者命令，命令输出经被利用的连接返回。

两个对复现和防御都很关键的实际点：

- **复现是概率性的。** 实验 RCE 依赖 ASLR 布局猜测（主导布局只在部分新进程里出现），外加严格的实验条件：官方 Node 24.22.0 x86-64 non-PIE 二进制（实验 Dockerfile 里用 digest 钉死）、Express 5.3.0 + body-parser 2.4.0、`UV_THREADPOOL_SIZE=1`、会重启 worker 的 supervisor、已接受的 socket 文件描述符。我们的第 1 轮 16 次全失败，第 2 轮才通过。第一次没复现出来**不代表目标安全**。
- **这是运行时漏洞，不是应用漏洞。** 任何在脆弱版 Node 上把攻击者可控 Brotli 数据交给 `node:zlib` 的应用，都会经这条路径暴露。应用层过滤不能替代 Node 升级。

## FixLab 验证

全部实验均在自有靶场服务器的隔离 Docker 容器里完成，只绑回环地址（`127.0.0.1`）。没有碰任何第三方系统，没有用真实凭证。

### 受影响版：Node 24.22.0 — RCE 验证通过

- **目标：** Express 5.3.0（body-parser 2.4.0）+ `express.json()`，`POST /upload`（JSON，默认 100kb 体积上限），`GET /health` 回 `PONG`，`127.0.0.1:3000`，supervisor 循环重启 Node，`UV_THREADPOOL_SIZE=1`，官方 Node 24.22.0 x86-64 non-PIE 二进制（实验 Dockerfile 里用 digest 钉死）。
- **工具：** dimasma0305 的公开 PoC，profile 为 `node-24.22.0-express-5.3.0-bookworm-x86_64`（仅标准库，宿主机 Python 3.10 直接跑），每轮最多试 16 个新 supervisor 进程。
- **攻击面：** `POST /upload` 带 `Content-Encoding: br` 的 Brotli 体；body-parser 经 `node:zlib` 解压 → 越界写 → ROP 链（`dup2` 到已接受的 socket fd 19 → `execvp`）→ `id` 命令输出经被利用的 HTTP 连接返回。
- **结果（第 1 轮 16/16 失败；第 2 轮第 3 次尝试 PASS）：**
  - 第 1 轮：16 次全失败（staged 位置稳定在 `0x137ed748`，每轮以 network crash trigger 重置新进程，最后响应为空）。
  - 第 2 轮第 3 次：`PASS: RCE verified by fresh id output through the declared interface`——证明通道为 HTTP 请求 socket 的 stdout，证明命令为 `id`，证明输出为 `uid=1000(node) gid=1000(node) groups=1000(node)`。
- **结论：** CVE-2026-111497 在这个 Express + Node 24.22.0 环境上可端到端 RCE（Brotli 越界写 → ROP → 以 Node 用户身份任意命令执行）。

### 修复版：Node 24.22.1 — 被阻断

- **目标：** 同一个实验，只把 Dockerfile 基础镜像换成 `node:24.22.1-bookworm`（Express 与 body-parser 配置不动，隔离变量只剩 Node 版本）；版本经一次性容器确认过是 `v24.22.1`；`127.0.0.1:3000`。
- **结果：** 同一个 PoC 返回 FAIL——`network crash trigger did not stop the current Express worker`（恶意输入不再让 worker 崩溃，利用链无法启动；PoC 在第 1 次尝试后即中止）。PoC 跑完后服务还活着：`/health` 回 `PONG`，正常 `/upload` 回 `DONE`。
- **结论：** Node 24.22.1 挡住了这个利用，且服务保持存活。升级到你所在分支的修复版本。

### 诚实边界 — 我们没 claim 的东西

- 第 1 轮 16/16 失败是概率型 ASLR 猜测的方差（与 PHP 实验在 2 核主机上的情况同理），不是安全的证据。第 2 轮通过了，这个结果才算数。
- 我们只验证了 Express 网络直达 RCE 这一个 profile。同仓库的其他 profile（stock Node 的 DoS profile，以及 worker/fetch/next/undici/axios 实验）本次没有跑；不要把这篇当成覆盖了它们。
- 早期二手报道称该仓库只验证了 DoS；我们以仓库当前 README（2026-10-23 更新）与 profiles 数据为准，其中该 Express profile 标注为 RCE 已验证。
- 本仓库**不发布可直接用的武器化 exploit**。机制讲清楚是为了让防守方能检测和修复；验证用的是公开 PoC，在隔离实验里跑的。

## 检测 — 怎么查自己是否受影响

1. **最快：查版本。** 跑 `node --version`。如果是 22.x（22.23.4 之前）、24.x（24.22.1 之前）或 26.x（26.12.1 之前），即视为受影响，马上升级。
2. **查可达性：** 有没有应用路径会解压攻击者可控的 Brotli 数据？查 `Content-Encoding: br` 请求处理、`fetch()` 拉取不受信任响应、直接对不受信任输入调 `zlib`。修复前 Node 上存在这类路径，即视为漏洞可达。
3. **查入侵痕迹（如果你曾把受影响构建暴露在外）：** 短时间内 Node worker 反复崩溃或重启、以 Node 用户身份运行的不明进程、Node worker 的不明外联。任一命中即视为可能已被入侵——不要只升级就了事，应从干净镜像重建。
4. 不要拿来路不明的 PoC 去打生产系统“测试”。先查版本，再打补丁。

## 修复与处置

1. **升级 Node 到你所在分支的修复版本：22.23.4、24.22.1 或 26.12.1（或更高版本）。** 这就是修复。
2. 容器镜像从修复后的基础镜像重建——不要只给运行中的容器打补丁还留着旧层。
3. 如果主机曾把受影响构建暴露在外，先按上面“检测”一节查入侵痕迹，查不清楚就重建，不要只升级就宣布干净。
4. 纵深上可以审计攻击者可控 Brotli 数据进入应用的位置（br 编码请求体、拉取的响应）——但 Node 升级才是修复，输入过滤不能替代它。

## 参考

- CVE-2026-111497 — Node.js Brotli 解码器越界写 → RCE（CVSS 9.2）。
- Node.js 安全公告（受影响分支 22.x / 24.x / 26.x 与修复版本 22.23.4 / 24.22.1 / 26.12.1）。
- Brotli 解码器错误 `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`（-17）；修复版 Node 的 `ERR__ERROR_FORMAT_BLOCK_SWITCH`。
- 本实验所用的公开 PoC（隔离环境、仅回环）：https://github.com/dimasma0305/CVE-2026-111497-POC

## 关于 FixLab

FixLab（飞克实验室）是漏洞研究与修复服务：我们报告的每个漏洞都在自有隔离靶场里复现过，每套修复方案都端到端跑通过才发布。跑不通的修复，我们会明说跑不通，不会硬 claim。

- 官网：https://vfixlab.com
- FixLab 已验证的其他漏洞：[PHP2Shell（CVE-2026-109618 / CVE-2026-109619）](https://github.com/wonghunghingp-ops/vfixlab1) · [LiteLLM 1.107.0 供应链投毒](https://github.com/wonghunghingp-ops/vfixlab3) · [Cursor 木马化扩展](https://github.com/wonghunghingp-ops/vfixlab4) · [GitLab Onigmo（CVE-2026-97229）](https://github.com/wonghunghingp-ops/vfixlab5)

本站内容可署名 FixLab 并附 https://vfixlab.com 链接后分享。
