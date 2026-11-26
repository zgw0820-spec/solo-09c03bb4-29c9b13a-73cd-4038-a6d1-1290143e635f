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
7. **无 RTR/VRP 增量同步**：不会主动连 rpki-rtr 缓存或验证器拉增量，
   授权更新靠“提交候选整表 → 试算 → 启用”，或替换挂载种子后重启。
8. **可观测性较轻**：只有 `/healthz` 与结构化 JSON 日志（uvicorn），
   未接 Prometheus 指标/OpenTelemetry；试算历史只保留在内存中的候选对象内。
9. **演示地址为文档网段**：种子与剧本使用 192.0.2.0/24、198.51.100.0/24、
   203.0.113.0/24、198.18.0.0/16 等保留网段和 AS650xx 示例 ASN；
   接生产前需把 `data/active_table.json` 换成验证器实际导出。
