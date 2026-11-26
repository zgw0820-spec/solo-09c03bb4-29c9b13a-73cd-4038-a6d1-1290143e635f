# RPKI Cut-over Guard（授权表切换守门服务）

换 RPKI 验证器前，边界网管用来确认：**新的候选授权整表不会让当前原本放行的 BGP 路由变成 Invalid**。

- FastAPI 单实例服务，接收采集器转发的 **IPv4 BGP 通告 / 撤回**
- 路由以 **`(prefix, origin_asn)`（前缀 + 起源 ASN）** 唯一区分
- 预置当前生效授权表；授权记录为验证器已核验的 `prefix / max_length / origin_asn`（ROA 语义）
- 标准 RPKI 起源判定：`Valid` / `Invalid` / `NotFound`
- 支持候选整表试算、返回授权版号与“将新增为 Invalid”的路由
- 启用时校验试算新鲜度，并**始终按启用瞬间仍在播的路由重核**
- 有新增 Invalid → `409 ENABLE_BLOCKED`，保留原表并列出阻断项；否则原子切表
- 核对期间通告/撤回照常接收，通告回执按**当时生效的表**判定（带版本号）

---

## 1. 用 Docker Compose 启动（推荐）

```bash
docker compose up --build
# 服务监听 http://127.0.0.1:8000
# Swagger UI:  http://127.0.0.1:8000/docs
# 健康检查:    curl http://127.0.0.1:8000/healthz
```

Compose 会：

- 用仓库内 `Dockerfile` 构建（`uvicorn --workers 1`，内存态要求单 worker）
- 把 `./data` 只读挂载到 `/app/data`，可用你从验证器导出的生效表直接替换
  `data/active_table.json`，无需重建镜像（路径由环境变量 `RPKI_SEED_PATH` 指定）
- 配置容器健康检查

停止：`docker compose down`。

> 说明：路由、候选与试算令牌保存在单进程内存中，重启后回到种子表（见
> `DELIVERY.md` 的“未完成事项”）。

## 2. 本地直接运行（无需 Docker）

需要 Python 3.11：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt   # 含测试依赖
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

另开终端跑端到端 API 演示（建议对**全新启动**的实例运行）：

```bash
bash scripts/demo_requests.sh
# 或指定地址：bash scripts/demo_requests.sh http://other-host:8000
```

演示的完整真实输出已保存在 `demo/demo_run.log`；自动化测试日志在
`demo/pytest_run.log`。

运行测试：

```bash
.venv/bin/python -m pytest -q
```

---

## 3. 判定规则

对路由 `(route_prefix, route_len, origin_asn)` 与授权记录
`(roa_prefix, max_length, asn)`：

1. **覆盖**：`route_prefix ⊆ roa_prefix` 且 `route_len ≥ roa_prefix_len`。
2. **Valid**：存在覆盖记录，其 `asn == origin_asn` 且
   `route_len ≤ max_length`。
3. **Invalid**：存在一条或多条覆盖记录，但没有任何一条同时满足 ASN 与最大长度条件。
   返回细分原因：
   - `origin_as_unauthorized`（长度条件满足但 ASN 不匹配）
   - `max_length_exceeded`（ASN 匹配但前缀长度超 maxLength）
   - `origin_as_or_max_length_mismatch`（其余组合）
4. **NotFound**：没有任何覆盖记录，单列。

**“新增 Invalid / 阻断项”的口径**：当前生效表下为 `Valid` **或** `NotFound`
（即 RPKI 口径中原本放行），而候选表下为 `Invalid` 的在播路由。
两张表下都已经是 `Invalid` 的路由不属于“新增”，不会阻断本次切换。

前缀必须是规范的严格 IPv4 前缀（拒绝主机位与 IPv6）；
`max_length` 必须满足 `prefix_length ≤ max_length ≤ 32`；
ASN 接受整数或 `"AS65001"` 形式（0–4294967295，含 ROA AS0）。

授权表“版号”有两个标识：

- `version`：验证器导出时带的人类可读版本标签（未提供则用内容指纹派生）
- `fingerprint`：整表规范化记录（排序去重）的 SHA-256 短指纹，是内容是否变化的权威依据

试算结果同时返回候选的 `authorization_version / authorization_fingerprint`
和试算基准 `active_version_at_trial / active_fingerprint_at_trial`。

---

## 4. API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz`（别名 `/health`） | 版本、在播路由数、当前表下 Invalid 数 |
| GET | `/api/active/authorizations` | 当前生效授权整表（含版本/指纹） |
| GET | `/api/routes?state=valid\|invalid\|not_found` | 在播路由及按现表的判定 |
| POST | `/api/bgp/announcements` | 接收 IPv4 BGP 通告，同步返回按当时生效表的判定 |
| POST | `/api/bgp/withdrawals` | 撤回 `(prefix, origin_asn)`；省略 `origin_asn` 则撤回该前缀所有起源 |
| POST | `/api/candidates` | 提交候选整表（可带 `candidate_id`），立即试算，返回 `201` + trial |
| PUT | `/api/candidates/{candidate_id}` | 提交/整体替换同一候选，自动重新试算；旧 trial 令牌随即失效 |
| GET | `/api/candidates` / `.../{id}` | 候选列表 / 详情（含最新试算） |
| POST | `/api/candidates/{id}/trial` | 授权版变化后重做试算，返回新 trial 令牌 |
| POST | `/api/candidates/{id}/enable` | 新鲜度校验 + 在播路由重核 + 原子切表 |

统一错误体：`{"detail": {"code": "...", "message": "...", ...}}`。

启用可能返回的冲突码：

- `TRIAL_REQUIRED`：候选还没有试算
- `TRIAL_NOT_FOUND`：传入的 trial 令牌不属于该候选
- `RETRIAL_REQUIRED` / `reason=candidate_authorization_changed`：
  试算后候选的版本号或记录内容已变（**授权版已变，必须重做试算**）
- `RETRIAL_REQUIRED` / `reason=active_table_changed`：试算基准生效表已被别的切换改变
- `ENABLE_BLOCKED`：授权版未变，但启用时重核发现新 Invalid；`blockers[]` 列出阻断项

---

## 5. API 演示请求（可直接复制）

设 `B=http://127.0.0.1:8000`。

### 5.1 通告与撤回（回执按当前生效表判定）

```bash
# Valid：192.0.2.0/24 + AS65001 命中种子 ROA
curl -sS -X POST $B/api/bgp/announcements \
  -H 'Content-Type: application/json' \
  -d '{"prefix":"192.0.2.0/24","origin_asn":65001,"collector":"c1"}' | jq

# NotFound：种子表无 198.18.0.0/16 的覆盖授权，当前放行
curl -sS -X POST $B/api/bgp/announcements \
  -H 'Content-Type: application/json' \
  -d '{"prefix":"198.18.0.0/16","origin_asn":65010}' | jq

# 撤回精确的 (前缀, ASN)
curl -sS -X POST $B/api/bgp/withdrawals \
  -H 'Content-Type: application/json' \
  -d '{"prefix":"198.18.0.0/16","origin_asn":65010}' | jq
```

### 5.2 提交候选整表并试算

```bash
curl -sS -X PUT $B/api/candidates/cutover \
  -H 'Content-Type: application/json' \
  -d '{
    "version": "2026-11-26-v2",
    "records": [
      {"prefix":"192.0.2.0/24","max_length":25,"origin_asn":65001},
      {"prefix":"198.51.100.0/24","max_length":28,"origin_asn":65002},
      {"prefix":"203.0.113.0/24","max_length":24,"origin_asn":65003},
      {"prefix":"198.18.0.0/16","max_length":24,"origin_asn":65010}
    ]
  }' | jq '.trial | {trial_id, authorization_version, authorization_fingerprint,
                     routes_evaluated, new_invalid_count, new_invalid}'
```

### 5.3 启用：新通告阻断的典型情形

```bash
TID=$(curl -sS $B/api/candidates/cutover | jq -r '.latest_trial_id')

# 试算之后新到一条“候选表会判 Invalid、现表却放行”的通告
curl -sS -X POST $B/api/bgp/announcements -H 'Content-Type: application/json' \
  -d '{"prefix":"198.18.1.0/24","origin_asn":65099}' | jq '.validation.state, .active_version'
# => "not_found" / "2026-11-26-active-1"（回执仍按旧表，放行）

# 启用 -> 409 ENABLE_BLOCKED，blockers 列出该路由，旧表保留
curl -sS -X POST $B/api/candidates/cutover/enable \
  -H 'Content-Type: application/json' -d "{\"trial_id\":\"$TID\"}" | jq

# 撤回阻断路由后，同一 trial 令牌再次启用 -> 200 切表
curl -sS -X POST $B/api/bgp/withdrawals -H 'Content-Type: application/json' \
  -d '{"prefix":"198.18.1.0/24","origin_asn":65099}' >/dev/null
curl -sS -X POST $B/api/candidates/cutover/enable \
  -H 'Content-Type: application/json' -d "{\"trial_id\":\"$TID\"}" | jq
```

### 5.4 授权版变化必须重做试算

```bash
# PUT 同一 candidate_id 替换整表后，旧 trial_id 启用：
curl -sS -X POST $B/api/candidates/cutover/enable \
  -H 'Content-Type: application/json' -d '{"trial_id":"<旧 trial_id>"}'
# => 409 RETRIAL_REQUIRED, reason=candidate_authorization_changed

# 重新试算，用新令牌启用
curl -sS -X POST $B/api/candidates/cutover/trial | jq -r '.trial_id'
```

更完整、可一键执行的剧本见 `scripts/demo_requests.sh`。

---

## 6. 设计与并发

- `app/rpki.py`：纯函数判定 + 指纹 + 新增 Invalid 差分，无框架依赖
- `app/store.py`：单例内存状态，`threading.RLock` 串行化所有状态变迁
- `app/main.py`：薄 FastAPI 路由；同步路由在线程池中运行，锁保证一致性
- 切表是锁内的引用替换：通告要么发生在切表前（进重核集合、按旧表判定），
  要么发生在切表后（按新表判定），不存在“判定表”和“生效表”错位的窗口
- 因此部署必须保持 **单进程 / 单 worker**（Dockerfile 已固定 `--workers 1`）

## 7. 目录结构

```
app/
  main.py            # FastAPI 路由与错误处理
  models.py          # Pydantic 入参/校验（IPv4 前缀、ASN、maxLength）
  rpki.py            # ROA 覆盖/Valid/Invalid/NotFound 与差分
  store.py           # 线程安全单例：生效表、在播路由、候选、trial、启用
data/active_table.json   # 预置生效表（可挂载替换）
scripts/demo_requests.sh # 端到端 API 演示剧本
tests/test_service.py    # 18 个 API/规则测试
demo/demo_run.log        # 演示真实输出
demo/pytest_run.log      # 测试真实输出
Dockerfile
docker-compose.yml
requirements*.txt
DELIVERY.md          # 实现内容 / 实测结果 / 未完成事项
```
