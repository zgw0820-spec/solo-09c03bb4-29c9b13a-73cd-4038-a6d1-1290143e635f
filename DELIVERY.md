# 交付说明：RPKI Cut-over Guard

日期：2026-11-26　形态：FastAPI 单实例服务 + Docker Compose 交付

---

## 一、实现内容

### 1. 需求对照

| 需求 | 实现 |
| --- | --- |
| FastAPI 单实例 | `app/main.py`；Dockerfile/Compose 固定 `uvicorn --workers 1`，状态为进程内单例 |
| 接收 IPv4 BGP 通告/撤回 | `POST /api/bgp/announcements`、`POST /api/bgp/withdrawals`；严格校验 IPv4 规范前缀，拒绝 IPv6/主机位 |
| 以前缀 + 起源 ASN 区分路由 | 路由表键为 `(prefix, origin_asn)`；同前缀不同 ASN 视为不同路由，可分别撤回 |
| 预置生效表 | `data/active_table.json`（3 条种子 ROA，RFC5737 网段），启动时加载；`RPKI_SEED_PATH` 可换挂载文件 |
| 授权记录含前缀/最大长度/ASN | `RoaRecordIn`：`prefix`、`max_length`（校验 `前缀长 ≤ max_length ≤ 32`）、`origin_asn`（兼容 `"AS65001"`，含 AS0） |
| 覆盖 + ASN + 最大长度判 Valid | `app/rpki.py::evaluate_network`，用 `ipaddress` 的 `subnet_of` 做包含判定 |
| 有覆盖无符合项判 Invalid | 返回 `invalid` 及原因码 `origin_as_unauthorized` / `max_length_exceeded` / `origin_as_or_max_length_mismatch`，并附每条覆盖记录的 `asn_match/length_ok` |
| 无覆盖单列 | `not_found` 独立状态；`GET /api/routes?state=not_found` 可单筛 |
| 提交候选整表试算 | `POST /api/candidates`、`PUT /api/candidates/{id}`，整表替换并立即试算 |
| 返回所用授权版号 | trial 返回候选 `authorization_version` + 内容 `authorization_fingerprint`（规范化整表 SHA-256 短指纹），以及试算基准 `active_version_at_trial/fingerprint` |
| 返回将新增的无效路由 | trial 的 `new_invalid[]`（含前缀、ASN、旧/新状态、原因、覆盖项、首次/最近出现时间、采集器）与 `new_invalid_count` |
| “新增”口径 | 现表为 `valid` 或 `not_found`（原本放行）而候选为 `invalid`；两表下都已 invalid 的不算新增 |
| 授权版已变须重做试算 | 每次试算发 `trial_id` 令牌；启用时比对候选当前 version+指纹，不一致 → `409 RETRIAL_REQUIRED / candidate_authorization_changed`；另覆盖“基准生效表被别的切换改动” → `reason=active_table_changed` |
| 未变也按启用时仍在播路由重核 | `enable_candidate` 不信旧结论，始终用当前 `routes` 重算差分；因此试算后的新通告会阻断，试算阻断项被撤回后同一令牌也可放行 |
| 有新增无效拒绝启用、保留原表、列阻断项 | `409 ENABLE_BLOCKED`，body 含 `blockers[]` 与 `recheck`；锁内在切表前抛出，活动表不变 |
| 否则切候选表 | 锁内原子替换活动记录/版本/指纹，返回 `200` 与 `previous_active_version → active_version` |
| 核对期间照常收通告/撤回 | 所有操作取同一把 `RLock`；通告在锁内按当时活动表判定，回执带 `active_version/fingerprint` |
| 通告回执按当时生效表判定 | 切表前后的回执版本号不同，演示第 1/6/11 步可直接对比 |
| Docker Compose 启动 | `Dockerfile` + `docker-compose.yml`（端口 8000、只读挂载 `./data`、healthcheck、单 worker） |
| 附 API 演示请求 | `scripts/demo_requests.sh` 一键剧本；`README.md` 第 5 节可复制 curl；Swagger `/docs` |
| 试跑“新通告阻止启用” | 已真实试跑，见下节；自动化测试 `test_new_announcement_after_clean_trial_blocks_enable` |
| 交付前核对改动 | 18 个测试全绿、`compileall` 通过、`git diff --check` 干净、逐文件自审（修掉一个重复 candidate_id 会变 500 的问题，改为全局 409） |

### 2. 文件清单

```
app/__init__.py
app/main.py            # 10 个 OpenAPI 路径 + 全局 StoreConflict→409
app/models.py          # Pydantic 校验模型
app/rpki.py            # 纯函数：前缀解析/覆盖/三态判定/指纹/新增 Invalid 差分
app/store.py           # 线程安全单例状态机（通告、撤回、候选、trial、启用）
data/active_table.json # 预置生效表 2026-11-26-active-1
tests/test_service.py  # 18 个 API 端到端测试（TestClient）
scripts/demo_requests.sh
demo/demo_run.log      # 22 次真实 HTTP 调用的完整输出
demo/pytest_run.log    # 18 passed 的详细日志
Dockerfile / docker-compose.yml / .dockerignore
requirements.txt / requirements-dev.txt
README.md / DELIVERY.md
```

---

## 二、实测结果（2026-11-26，本工作区真实执行）

### 实测环境

- Linux 容器，用户 `node`（无 root、无 sudo）
- 系统 Python 3.11.2；系统未装 pip/ensurepip，已用 `get-pip.py` 在
  `/workspace/.venv` 建独立虚拟环境并安装：
  fastapi 0.165.0、uvicorn 0.54.0、pydantic 2.14.4、httpx 0.29.0、pytest 9.2.0
- **本环境没有 docker / dockerd / docker compose 插件，也无法提权**，
  因此 `docker compose up --build` 未能在本机实跑（见“未完成事项”第 1 条）；
  服务用同一套 `requirements.txt` 依赖以 uvicorn 实跑验证。

### 1. 自动化测试

命令：`.venv/bin/python -m pytest -v`（完整输出见 `demo/pytest_run.log`）

结果：**18 passed**，覆盖：

- 种子表/健康检查
- Valid / Invalid（ASN 未授权、超 maxLength 两种原因）/ NotFound 参数化用例
- `"AS65001"` 格式、前缀+ASN 双键、省略 ASN 批量撤回、重复撤回幂等
- IPv6/主机位/maxLength<前缀长 的 422 校验
- 试算列出新增 Invalid
- **试算干净 → 新通告到达 → 启用被 ENABLE_BLOCKED → 撤回 → 同令牌启用成功 → 再通告按新表判 invalid**
- 候选授权 version/记录变化 → `RETRIAL_REQUIRED`
- 基准生效表被其他候选切换改变 → `RETRIAL_REQUIRED(active_table_changed)`
- trial 阻断项随撤回消失后同一令牌可启用
- 未知候选 404、重复 candidate_id 409、省略 trial_id 用最新 trial

### 2. 真实 HTTP 演示（新通告阻止启用）

启动：`.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000`
剧本：`bash scripts/demo_requests.sh`（完整输出见 `demo/demo_run.log`）

HTTP 状态统计：**20 个 200 + 2 个预期 409**，无 5xx；uvicorn 服务端日志无 error/traceback。

关键实测数据（摘自日志）：

1. 5 条基线通告回执按 `2026-11-26-active-1` 判定：
   `192.0.2.0/24,AS65001` 与 `/25` 更明细为 valid，
   `198.51.100.128/25,AS65002`、`203.0.113.0/24,AS65003` valid，
   `198.18.0.0/16,AS65010` not_found。
2. 候选 `cutover` 先提交 `2026-11-26-v2-rc1`（198.18 maxLength=16），
   再整体替换为 `2026-11-26-v2`（maxLength=24），新 trial
   `new_invalid_count = 0`。
3. 拿 rc1 的旧 trial 启用，实测：
   `409 RETRIAL_REQUIRED`，
   `reason=candidate_authorization_changed`，
   `changed_fields=["version","records"]`，并给出两版 version 与指纹。
4. `POST .../trial` 重算得到新令牌（仍 0 阻断，`routes_evaluated=5`）。
5. 试算后新到两条通告，回执在旧表下均为 `not_found`（照常接收/放行）：
   - `198.18.1.0/24, AS65099`（字符串 `"AS65099"` 入参）
   - `198.18.0.0/25, AS65010`
6. 授权版未变，用新令牌启用，实测 **`409 ENABLE_BLOCKED`**：
   `recheck.routes_checked = 7`、`new_invalid_count = 2`，阻断项：
   - `198.18.0.0/25/65010`：`not_found → invalid / max_length_exceeded`
     （覆盖 ROA `/16 maxLength=24 asn=65010`，`asn_match=true, length_ok=false`）
   - `198.18.1.0/24/65099`：`not_found → invalid / origin_as_unauthorized`
     （`asn_match=false, length_ok=true`）
7. 阻断后 `GET /healthz` 仍是 `active_version=2026-11-26-active-1`，原表确实保留。
8. 撤回这两条后，**同一 trial 令牌**再次启用：`200`，
   `routes_checked=5, new_invalid_count=0`，
   `previous_active_version=2026-11-26-active-1 → active_version=2026-11-26-v2`。
9. 再次通告 `198.18.1.0/24,AS65099`，回执变为
   `active_version=2026-11-26-v2`、`state=invalid`、
   `reason=origin_as_unauthorized` —— 证明切表真正生效。
10. 另测 `POST /api/candidates` 重复 id：实测结构化
    `409 {"code":"CANDIDATE_EXISTS",...}`（自审时发现该路径原先漏捕获会成 500，已修复并加测试）。

### 3. 其他核对

- `docker-compose.yml` 已用 PyYAML 解析校验，服务名/端口 `8000:8000`/挂载/healthcheck 字段正确。
- `/openapi.json` 可匿名获取，OpenAPI 3.1，10 个路径，`/docs` Swagger 可用。
- `.venv` 已加入 `.gitignore`，不会污染交付/构建上下文（`.dockerignore` 也排除）。
- `python -m compileall app tests` 通过；`git diff --check` 无空白问题。
- 改动均在工作区（新增文件，baseline 是空提交），**未执行 git commit**（未要求提交）。

### 4. 复核实验方式

```bash
# 自动化
.venv/bin/python -m pytest -q

# 起服务 + 完整剧本（全新实例）
.venv/bin/uvicorn app.main:app --port 8000 &
bash scripts/demo_requests.sh
# 或 docker compose up --build 后执行同一脚本
```

---

## 三、未完成事项 / 已知限制

1. **Docker Compose 未在本机构建实跑**：执行环境没有 docker daemon 且无 root，
   无法验证 `docker compose up --build` 的镜像构建与健康检查；目前只做了
   Compose YAML 解析校验，并用等价 Python 3.11 + 锁定版本依赖在 uvicorn 上
   完整实测。Dockerfile 仅用标准 `python:3.11-slim` + `pip install -r
   requirements.txt`，风险点主要是网络拉取基础镜像/PyPI。
2. **内存单例、无持久化**：BGP 在播路由、候选与 trial 令牌在进程重启后丢失，
   授权表回到 `data/active_table.json`（或 `RPKI_SEED_PATH`）种子。
   采集器通常会重放/重连；如需跨重启保留候选，需要加 SQLite/卷快照（未做）。
3. **严格单实例**：状态在进程内，不能多 worker/多副本水平扩展；
   若未来多实例，需把状态移到共享存储并加选主/事务。当前已在文档、
   Compose、Dockerfile 三处明确 `--workers 1`。
4. **无鉴权 / TLS / 审计落盘**：API 可直接改表，CORS 放开为 `*`，
   仅适合内网或演示；上线前应加网管侧认证授权、HTTPS 与操作审计。
5. **仅 IPv4**：按需求只接收/校验 IPv4，IPv6 前缀返回 422；
   数据模型与判定函数扩展 IPv6 不难，但本次明确不做。
6. **撤回语义的一个选择**：真实 BGP UPDATE 撤回通常只带前缀，因此
   `/api/bgp/withdrawals` 的 `origin_asn` 设计为可选——省略时撤回该前缀下
   所有起源 ASN；若采集器能稳定提供被撤回路由的起源 ASN，建议始终带 ASN
   精确撤回，避免误删同前缀其他起源。
7. **RTR 只做整表、不做增量 delta，也不向上游同步**：本次已新增面向边界
   路由器的 RFC 8210 RTR v1 TCP 接口（Reset 整表 / 精确 Serial 空更新 /
   否则 Cache Reset / Serial Notify，见第四节），但按需求**不做增量 PDU**；
   服务本身仍不会主动连 rpki-rtr 缓存或验证器拉数据，授权更新靠
   “提交候选整表 → 试算 → 启用”，或替换挂载种子后重启。
8. **可观测性较轻**：只有 `/healthz` 与结构化 JSON 日志（uvicorn），
   未接 Prometheus 指标/OpenTelemetry；试算历史只保留在内存中的候选对象内。
9. **演示地址为文档网段**：种子与剧本使用 192.0.2.0/24、198.51.100.0/24、
   203.0.113.0/24、198.18.0.0/16 等保留网段和 AS650xx 示例 ASN；
   接生产前需把 `data/active_table.json` 换成验证器实际导出。

---

# 四、追加交付：RFC 8210 RTR v1 TCP 取表接口（2026-11-26）

在原守门服务上，让边界路由器能通过标准 RTR 协议**直接读取已启用的 IPv4
起源授权**。代码、测试、演示均在本工作区真实跑过。

## 4.1 需求对照

| 需求 | 实现 |
| --- | --- |
| RFC 8210 **v1** RTR TCP 接口 | `app/rtr.py`：v1 PDU 编解码 + 线程版 TCP Server；随 FastAPI lifespan 启停，默认 `0.0.0.0:8282`（`RTR_ENABLED/RTR_HOST/RTR_PORT` 可调）；Compose 映射 `8282:8282`，Dockerfile `EXPOSE 8000 8282` |
| Reset Query 返回完整生效表（IPv4 Prefix） | `RTRConnection`：`Cache Response`(3) → 每条授权一个 20 字节 `IPv4 Prefix`(4，flags=0x01 通告) → v1 `End of Data`(7，length=12，带 serial)。记录去重并按前缀/长度/ASN 稳定排序 |
| Serial Query 会话号+序列号都匹配 → 空更新 | 单一 `Cache Response` + `End of Data`，中间 0 条 Prefix PDU |
| 否则 Cache Reset | session id 或 serial 任一与当前不一致（含落后 serial）→ 单个 8 字节 `Cache Reset`(8) |
| 本次不做增量 | 不保存/计算 delta；任何非精确匹配一律 Cache Reset，由路由器 Reset 整表重取 |
| 一次响应使用同一份表+同一序列号 | `store.rtr_snapshot()` 在锁内取不可变 `RtrSnapshot(session, serial, entries)`，整段响应只遍历该快照；发送期间不持锁 |
| 仅“启用使授权记录集合改变”才推进 serial + Serial Notify | 以整表指纹判定：`enable_candidate` 中 `records_changed = candidate.fingerprint != previous_fingerprint`，仅此时 `rtr_serial=(serial+1) mod 2^32`。纯换版本标签、重复启用、加入完全重复记录均不推进、不通知 |
| 传输中换表：发完本次响应再通知，只报最新 serial | 连接线程只在循环顶部/响应结束后的空闲点 `maybe_send_notify()`；比较当前 serial 与本响应快照 serial，**一次** Notify 携带当前最新值，连续多版合并 |
| 慢连接不拖住启用/其他路由器 | 每连接独立守护线程；启用路径完全不碰 socket、不持锁发送；慢 `sendall` 只阻塞该连接。有 6000 条记录 + 4KB 收发缓冲的真实 loopback 测试：慢连接卡住期间两次启用合计 `<2s`，另一连接完整取到新表，慢连接排空后仍收到旧整表 + EoD(serial=0) + **唯一一个** serial=2 的 Notify |
| Docker Compose 启动 | 更新 `docker-compose.yml`（8282 端口 + RTR 环境变量）与 `Dockerfile`；YAML 已解析校验。**但本机仍无 docker daemon，镜像构建/`compose up` 未实跑**（见 4.5） |
| 附本地 RTR 客户端 + 启用 API 请求，演示换版后重新取表 | `scripts/rtr_client.py`（纯标准库，`reset/serial/watch`，支持 `--json`、`--refetch`）与 `scripts/demo_rtr.sh`（curl 启用 + 客户端取表，含断言）；真实输出存 `demo/rtr_demo_run.log` |
| 交付前核对 + 自测 + 说明 | 28 个测试全绿、`compileall`、`git diff --check`、字节级报文核对、真实 uvicorn 多轮演示（见 4.3） |

## 4.2 改动/新增文件

```
app/rtr.py            # 新增：RFC8210 v1 编解码、PduReader、RTRConnection、RTRServer
app/store.py          # 改：rtr_session_id/rtr_serial/active_rtr_entries、
                      #     rtr_state()/rtr_snapshot()、启用时按指纹推进 serial、
                      #     health/active_table/enable 响应增加 rtr 信息
app/main.py           # 改：lifespan 启停 RTRServer；根路径自描述增加 rtr_tcp
scripts/rtr_client.py # 新增：本地标准库 RTR 客户端（reset/serial/watch --refetch）
scripts/demo_rtr.sh   # 新增：RTR 全流程断言式演示（可重复执行）
tests/test_rtr.py     # 新增：10 个 RTR 测试（含真实 socket 慢连接隔离）
docker-compose.yml    # 改：映射 8282、加 RTR_* 环境变量
Dockerfile            # 改：EXPOSE 8000 8282
README.md             # 改：新增第 6 节 RTR 说明、更新并发/目录/测试数
demo/rtr_demo_run.log  # 新增：一次全新实例的 RTR 演示完整输出
demo/pytest_run.log   # 更新：28 passed
demo/demo_run.log     # 重新生成：原 HTTP 演示仍为 20×200 + 2×预期 409
```

未新增第三方依赖（RTR 用标准库 `socket/struct/threading`，客户端同理），
`requirements*.txt` 不变。

## 4.3 实际验过什么（本工作区真实执行）

环境沿用系统 Python 3.11.2，用 `/tmp/getpip-bootstrap/get-pip.py`
（`python -I` 引导）在 `/workspace/.venv` 装了
`requirements-dev.txt`（fastapi 0.165.0 / uvicorn 0.54.0 / pydantic 2.14.4 /
httpx 0.29.0 / pytest 9.2.0）。

1. **自动化测试：28 passed**（原 18 + 新 10），日志 `demo/pytest_run.log`。
   新增 RTR 覆盖：
   - Reset 返回 CacheResponse + 3 个 IPv4 Prefix + length=12/serial=0 的 EoD，
     并逐字段核对（含 `192.0.2.0/24,maxLength25,AS65001,flags=1`、length=20）；
   - session+serial 精确匹配 → 仅 CacheResponse+EoD 的空更新；
   - serial 不符 / session 不符 → Cache Reset；
   - 空闲连接在内容性启用后收到 Serial Notify(session, serial=1)；
   - 经 **HTTP** `PUT candidate → enable` 也推进 serial 并产生 Notify；
   - 仅换版本标签 / 加完全重复记录 → serial 不动、0.8s 内无 Notify；
   - **确定性假 socket 测试**：在第 2 个 Prefix 发送钩子里连续启用两版，
     整段响应仍是旧快照/EoD serial=0，空闲点恰好补一个 serial=2 的 Notify，
     再轮询不重复发送；
   - **真实 TCP 慢连接测试**：6000 条记录、`SO_SNDBUF/SO_RCVBUF=4096`，
     客户端读 28 字节后停读 0.5s 确保服务端阻塞在发送中；此时两次启用
     合计耗时 `<2s`，另一个连接完整取到 serial=2 的 6002 条；慢连接排空后
     得到旧版 6000 条与 EoD serial=0，随后只有一个 serial=2 Notify，
     0.8s 内无第二个 PDU。
   - 该套件连续单独跑 3 次、全量套件连跑多次均稳定通过（慢测试无 flake）。
2. **真实进程演示**：用 `.venv/bin/uvicorn app.main:app` 实起服务，
   `bash scripts/demo_rtr.sh` 全部断言通过，日志 `demo/rtr_demo_run.log`：
   实测 session=52431、serial `0→1→2`，旧 serial 轮询与错 session 均
   `cache_reset`（客户端退出码 3），Reset 重取 Prefix 数 `3→4→5` 且新前缀
   在表，watch 连接收到
   `Serial Notify ... newest serial=2` 并自动重取到 `198.19.2.0/24`。
   同一实例**连跑两次**该剧本也通过（第二次正确地从 serial=2 走到 3→4，
   证明可重复、前缀选取会避开已用项）。
3. **原 HTTP 演示无回归**：全新实例重跑 `scripts/demo_requests.sh`，
   仍为 **20 个 HTTP 200 + 2 个预期 409**，无 5xx；启用响应新增的 `rtr`
   块可见且切到 v2 时 `serial_advanced=true`（日志已刷新）。
4. **报文级核对**：打印实际十六进制，与 RFC 8210 布局逐字节一致，例如
   IPv4 Prefix：
   `01 04 0000 00000014 01 18 19 00 c0000200 0000fde9`
   （v1/type4/len20/flags=通告/plen24/maxlen25/192.0.2.0/AS65001）；
   EoD/Notify 为 `01 07|00 sid 0000000c serial`。
5. **部署等价核对**：不带额外环境变量、按 Dockerfile 的 CMD
   （`uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1`）实跑，
   `/healthz` 含 rtr 字段，对 `127.0.0.1:8282` 的真实 Reset 成功；
   `docker-compose.yml` 用 PyYAML 解析通过，端口/环境变量/healthcheck
   字段正确。`python -m compileall app tests scripts/rtr_client.py` 通过，
   `git diff --check` 无空白问题。

## 4.4 设计要点（为什么慢连接/一致性成立）

- 状态只有一份（进程内 `store` 单例），RTR 不另存表：启用在 store 锁内
  同时替换 `active_records / active_fingerprint / active_rtr_entries /
  rtr_serial`，因此不存在“表内容与 serial 错位”。
- `rtr_snapshot()` 返回的 entries 是创建后不再修改、换版只整体替换的
  tuple；连接线程拿到后即可释放锁慢慢发。
- 启用线程只改内存，不遍历 RTR 连接、不写 socket，所以再慢的路由器也
  不会反压启用；通知不是启用时逐连接推送，而是各连接线程在安全点自行
  比对当前 serial，天然合并多次变化、且绝不会插在一个响应的 PDU 序列中间。
- accept 单线程 + 每连接守护线程；断线只在该线程内收尾，并会清理已结束
  的线程对象。

## 4.5 本轮仍未做 / 风险

1. **Docker 镜像构建与 `docker compose up --build` 仍未在本机实跑**：
   环境没有 docker/podman/nerdctl 与 `/var/run/docker.sock`，也无 root；
   只做了 Compose YAML 解析、Dockerfile 核对，并用等价的
   uvicorn 单 worker 命令实跑验证。Dockerfile 仍只依赖
   `python:3.11-slim` + `pip install -r requirements.txt`，主要外部风险是
   拉基础镜像/PyPI 网络。
2. **未与真实边界路由器/RTR 实现做互操作测试**（环境无 BIRD/FRR/
   Routinator/StayRTR 等，也无法用容器）。已按 RFC 8210 逐字节核对并用
   自研客户端/测试闭环；真实厂商实现的版本协商、TCP MD5/AO、异常 PDU
   容忍度仍建议在测试网验证。
3. **只讲 RTR v1，不做版本协商降级**：收到非 v1 PDU 回
   Unsupported Protocol Version(4) 的 Error Report 后关闭；没有实现 RFC
   的多版本探测/降级状态机，也未实现 v2/ASPA/BGPsec Router Key PDU。
4. **按需求不做增量 delta**：任何非精确 Serial Query 都 Cache Reset；
   超大表 + 大量路由器频繁落后时会重复整表传输（当前演示/内网规模无碍，
   生产大规模可再做序列号窗口与增量）。
5. **RTR 无认证/加密**：明文 TCP，未实现 RFC 8210 的 SSH/TLS 传输或
   TCP MD5；Compose 端口默认对所有映射网卡开放，仅适合可信网管内网。
6. **session_id/serial 仍是内存态**：进程重启后重新随机 session、serial
   从 0 开始；路由器会因 session 不符自动 Cache Reset 全量重取，语义正确，
   但 serial 不跨重启单调。持久化 serial/session 未做（与既有“内存单例、
   重启回种子”限制一致）。
7. **连接数/限速/慢连接资源上限较轻**：线程-per-连接，未加最大连接数、
   读超时截断（仅 0.2s 轮询，慢速分片请求可长期占用一个线程）与出口队列；
   应对可信内网少量边界路由器足够，暴露到公网前需要加限制。
8. 既有第一、三节中的其他限制（无持久化候选/路由、单 worker、无 HTTP
   鉴权/CORS `*`、仅 IPv4 等）维持不变。
9. 改动均在工作区，**未执行 git commit**（未要求提交）。
