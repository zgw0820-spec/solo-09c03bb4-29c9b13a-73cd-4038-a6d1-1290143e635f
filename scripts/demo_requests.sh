#!/usr/bin/env bash
# =============================================================================
# RPKI Cut-over Guard —— 端到端 API 演示
#
# 演示主线：
#   1) 采集器通告若干基线路由，回执按当前生效表判定（valid/not_found）
#   2) 提交同一候选的两个授权版（rc1 -> rc2），拿到试算令牌
#   3) 用旧版试算令牌启用 -> 409 RETRIAL_REQUIRED（授权版已变，必须重做试算）
#   4) 重新试算（此时无新增 Invalid）
#   5) 试算后新到两条通告，在旧表下均放行（not_found）
#   6) 用未变化的授权版启用 -> 409 ENABLE_BLOCKED，列出两条阻断项，原表保留
#   7) 核对生效表版本未变
#   8) 撤回两条阻断路由，同一试算令牌再次启用 -> 200，切到候选表
#   9) 再次通告该越权 ASN 路由 -> 回执按新表判 invalid
#
# 用法：
#   bash scripts/demo_requests.sh [BASE_URL]
#   BASE_URL=http://127.0.0.1:8000 bash scripts/demo_requests.sh
# =============================================================================
set -u

BASE_URL="${1:-${BASE_URL:-http://127.0.0.1:8000}}"
LAST_JSON=""
LAST_CODE=""

# 等待服务就绪（curl 自身重试，不依赖 sleep 命令）
curl -fsS --retry 30 --retry-connrefused --retry-delay 1 \
  "$BASE_URL/healthz" -o /dev/null || {
    echo "service not reachable at $BASE_URL" >&2
    exit 1
  }

call() {
  local method="$1" path="$2" body="${3:-}"
  echo
  echo "----------------------------------------------------------------------"
  echo ">>> $method $path"
  if [[ -n "$body" ]]; then
    echo "    request body:"
    echo "$body" | jq . 2>/dev/null| sed 's/^/      /' || echo "      $body"
  fi
  local tmp
  tmp="$(mktemp)"
  if [[ -n "$body" ]]; then
    LAST_CODE=$(curl -sS -o "$tmp" -w '%{http_code}' \
      -X "$method" -H 'Content-Type: application/json' \
      -d "$body" "$BASE_URL$path")
  else
    LAST_CODE=$(curl -sS -o "$tmp" -w '%{http_code}' \
      -X "$method" "$BASE_URL$path")
  fi
  LAST_JSON="$(cat "$tmp")"
  rm -f "$tmp"
  echo "<<< HTTP $LAST_CODE"
  echo "$LAST_JSON" | jq . 2>/dev/null | sed 's/^/  /' || echo "$LAST_JSON"
}

banner() {
  echo
  echo "======================================================================"
  echo " $1"
  echo "======================================================================"
}

banner "0. 健康检查与预置生效表"
call GET /healthz
call GET /api/active/authorizations

banner "1. 采集器推送基线 BGP 通告（回执按 active-1 判定）"
call POST /api/bgp/announcements \
  '{"prefix":"192.0.2.0/24","origin_asn":65001,"collector":"collector-a","peer":"198.51.100.1"}'
call POST /api/bgp/announcements \
  '{"prefix":"192.0.2.128/25","origin_asn":65001,"collector":"collector-a"}'
call POST /api/bgp/announcements \
  '{"prefix":"198.51.100.128/25","origin_asn":65002,"collector":"collector-b"}'
call POST /api/bgp/announcements \
  '{"prefix":"203.0.113.0/24","origin_asn":65003}'
call POST /api/bgp/announcements \
  '{"prefix":"198.18.0.0/16","origin_asn":65010}'

banner "2. 提交候选 cutover 的 rc1 整表并试算"
call PUT /api/candidates/cutover '{
  "version": "2026-11-26-v2-rc1",
  "description": "新验证器导出的候选表（草案：198.18/16 maxLength=16）",
  "records": [
    {"prefix": "192.0.2.0/24", "max_length": 25, "origin_asn": 65001},
    {"prefix": "198.51.100.0/24", "max_length": 28, "origin_asn": 65002},
    {"prefix": "203.0.113.0/24", "max_length": 24, "origin_asn": 65003},
    {"prefix": "198.18.0.0/16", "max_length": 16, "origin_asn": 65010}
  ]
}'
TRIAL_RC1="$(echo "$LAST_JSON" | jq -r '.trial.trial_id')"
echo "    [captured] TRIAL_RC1=$TRIAL_RC1"

banner "3. 同一候选更新为 rc2 整表（maxLength 调整为 24），自动试算：无新增 Invalid"
call PUT /api/candidates/cutover '{
  "version": "2026-11-26-v2",
  "description": "新验证器导出的候选表（终稿：198.18/16 maxLength=24）",
  "records": [
    {"prefix": "192.0.2.0/24", "max_length": 25, "origin_asn": 65001},
    {"prefix": "198.51.100.0/24", "max_length": 28, "origin_asn": 65002},
    {"prefix": "203.0.113.0/24", "max_length": 24, "origin_asn": 65003},
    {"prefix": "198.18.0.0/16", "max_length": 24, "origin_asn": 65010}
  ]
}'
TRIAL_RC2="$(echo "$LAST_JSON" | jq -r '.trial.trial_id')"
echo "    [captured] TRIAL_RC2=$TRIAL_RC2"
echo "    trial.new_invalid_count = $(echo "$LAST_JSON" | jq -r '.trial.new_invalid_count')"

banner "4. 用 rc1 的旧试算令牌启用 —— 授权版已变，预期 409 RETRIAL_REQUIRED"
call POST /api/candidates/cutover/enable "{\"trial_id\":\"$TRIAL_RC1\"}"

banner "5. 授权版未再变化，显式重做试算，取得新令牌"
call POST /api/candidates/cutover/trial
TRIAL_FRESH="$(echo "$LAST_JSON" | jq -r '.trial_id')"
echo "    [captured] TRIAL_FRESH=$TRIAL_FRESH"

banner "6. 试算后新到两条通告：旧生效表无覆盖 -> 回执均为 not_found（照常放行）"
call POST /api/bgp/announcements '{
  "prefix": "198.18.1.0/24",
  "origin_asn": "AS65099",
  "collector": "collector-c",
  "peer": "198.51.100.9"
}'
call POST /api/bgp/announcements '{
  "prefix": "198.18.0.0/25",
  "origin_asn": 65010,
  "collector": "collector-c"
}'

banner "7. 授权版未变，用新令牌启用 —— 按启用时仍在播路由重核，预期 409 ENABLE_BLOCKED"
call POST /api/candidates/cutover/enable "{\"trial_id\":\"$TRIAL_FRESH\"}"

banner "8. 阻断后核对：生效表仍是旧版 active-1；这两条路由在现表下仍非 invalid"
call GET /healthz
call GET '/api/routes?state=not_found'

banner "9. 采集器撤回两条阻断路由"
call POST /api/bgp/withdrawals \
  '{"prefix":"198.18.1.0/24","origin_asn":65099,"collector":"collector-c"}'
call POST /api/bgp/withdrawals \
  '{"prefix":"198.18.0.0/25","origin_asn":65010}'

banner "10. 同一试算令牌再次启用：重核无新增 Invalid，预期 200 并切到 v2"
call POST /api/candidates/cutover/enable "{\"trial_id\":\"$TRIAL_FRESH\"}"

banner "11. 切表后该越权 ASN 路由再次通告 —— 回执现在按 v2 判 invalid"
call POST /api/bgp/announcements '{
  "prefix": "198.18.1.0/24",
  "origin_asn": 65099,
  "collector": "collector-c"
}'

banner "12. 收尾状态"
call GET /healthz
call GET /api/active/authorizations

echo
echo "======================================================================"
echo " 演示完成。Swagger UI: $BASE_URL/docs"
echo "======================================================================"
