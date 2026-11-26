#!/usr/bin/env bash
# =============================================================================
# RPKI Cut-over Guard —— RFC 8210 RTR v1 取表演示
#
# 演示主线（边界路由器视角）：
#   1) RTR Reset Query 取完整生效表（IPv4 Prefix PDU + v1 End of Data）
#   2) 用当前 session/serial 发 Serial Query -> 空更新
#   3) 通过“启用 API”启用一张新增一条授权的候选表 -> RTR serial +1
#   4) 路由器拿旧 serial 发 Serial Query -> Cache Reset
#   5) 重新 Reset Query 取到换版后的完整表
#   6) 用新 serial 轮询 -> 空更新
#   7) 常驻 watch 连接在第二次启用时异步收到 Serial Notify（只报最新 serial），
#      并自动重新取表
#
# 用法：
#   bash scripts/demo_rtr.sh [BASE_HTTP_URL]
#   RTR_HOST=127.0.0.1 RTR_PORT=8282 bash scripts/demo_rtr.sh
#
# 仅依赖 bash/curl/jq 和一个 Python 3（RTR 客户端只用标准库）。
# =============================================================================
set -u

BASE_URL="${1:-${BASE_URL:-http://127.0.0.1:8000}}"
RTR_HOST="${RTR_HOST:-127.0.0.1}"
RTR_PORT="${RTR_PORT:-8282}"
PY="${PYTHON:-python3}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT="$SCRIPT_DIR/rtr_client.py"
STAMP="$(date +%H%M%S)"

banner() {
  echo
  echo "======================================================================"
  echo " $1"
  echo "======================================================================"
}

fail() {
  echo "DEMO FAILED: $*" >&2
  exit 1
}

# Pick a 198.19.N.0/24 prefix not yet present in the active table, so the
# demo is repeatable and every enable genuinely changes the record set.
pick_extra_prefix() {
  local used n
  used="$(curl -fsS "$BASE_URL/api/active/authorizations" | jq -r '.records[].prefix')" \
    || fail "cannot read active authorizations"
  for n in $(seq 1 254); do
    if ! grep -qx "198\.19\.$n\.0/24" <<<"$used"; then
      echo "198.19.$n.0/24"
      return 0
    fi
  done
  return 1
}

enable_additive_candidate() {
  # $1 = candidate id, $2 = extra prefix, $3 = version label
  local cid="$1" prefix="$2" version="$3" body put tid code resp
  body="$(curl -fsS "$BASE_URL/api/active/authorizations" \
    | jq --arg p "$prefix" --arg v "$version" \
      '{version:$v,
        description:"RTR demo: additive enable",
        records:(.records + [{prefix:$p,max_length:24,origin_asn:65088}])}')"
  put="$(curl -fsS -X PUT "$BASE_URL/api/candidates/$cid" \
    -H 'Content-Type: application/json' -d "$body")"
  tid="$(jq -r '.trial.trial_id' <<<"$put")"
  # Additive prefix is in unused documentation space -> recheck has no blockers.
  resp="$(curl -sS -w '\n%{http_code}' -X POST \
    "$BASE_URL/api/candidates/$cid/enable" \
    -H 'Content-Type: application/json' -d "{\"trial_id\":\"$tid\"}")"
  code="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"
  echo "$resp"
  [[ "$code" == "200" ]] || fail "enable $cid returned HTTP $code: $resp"
}

# ---- wait for HTTP service --------------------------------------------------
curl -fsS --retry 30 --retry-connrefused --retry-delay 1 \
  "$BASE_URL/healthz" -o /dev/null || fail "HTTP service not reachable at $BASE_URL"

# ---- 1. initial Reset Query -------------------------------------------------
banner "1. 边界路由器启动：RTR Reset Query 取完整生效表"
for _ in $(seq 1 30); do
  RESET1="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" reset --json 2>/dev/null)" \
    && break
  sleep 1
done
[[ -n "${RESET1:-}" ]] || fail "RTR interface not reachable at $RTR_HOST:$RTR_PORT"
$PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" reset || true

SID="$(jq -r '.session_id' <<<"$RESET1")"
S0="$(jq -r '.serial' <<<"$RESET1")"
CNT0="$(jq -r '.prefix_count' <<<"$RESET1")"
echo "    [captured] session_id=$SID serial=$S0 prefix_count=$CNT0"
[[ "$(jq -r '.status' <<<"$RESET1")" == "end_of_data" ]] || fail "reset status"
[[ "$CNT0" -ge 3 ]] || fail "expected at least 3 seed PDUs, got $CNT0"

# ---- 2. Serial Query matching current -> empty update -----------------------
banner "2. Serial Query(session=$SID, serial=$S0) 与当前一致：空更新"
EMPTY="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" \
  serial "$S0" --session "$SID" --json)"
echo "$EMPTY" | jq '{status, session_id, serial, prefix_count}'
[[ "$(jq -r '.status' <<<"$EMPTY")" == "empty_update" ]] || fail "expected empty_update"

# ---- 3. enable API request: additive authorization --------------------------
P1="$(pick_extra_prefix)" || fail "no free demo prefix"
banner "3. 网管启用 API：在现表上新增 $P1 AS65088 并启用（serial 应推进）"
ENABLE1="$(enable_additive_candidate "rtr-demo" "$P1" "rtr-demo-$STAMP-a")"
echo "$ENABLE1" | jq '{enabled, active_version, previous_active_version, rtr}'
[[ "$(jq -r '.rtr.serial_advanced' <<<"$ENABLE1")" == "true" ]] || fail "serial should advance"
[[ "$(jq -r '.rtr.serial' <<<"$ENABLE1")" == "$((S0 + 1))" ]] || fail "serial should be S0+1"

# ---- 4. old serial poll -> Cache Reset --------------------------------------
banner "4. 路由器仍拿旧 serial=$S0 轮询：序列号不匹配 -> Cache Reset"
set +e
STALE="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" \
  serial "$S0" --session "$SID" --json)"
STALE_RC=$?
set -e
echo "$STALE" | jq '{status}'
echo "    rtr_client exit code = $STALE_RC (3 denotes Cache Reset)"
[[ "$STALE_RC" == "3" && "$(jq -r '.status' <<<"$STALE")" == "cache_reset" ]] \
  || fail "expected cache_reset (rc=3)"

# Wrong session id must likewise yield Cache Reset.
set +e
BADSESS="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" \
  serial "$((S0 + 1))" --session "$((SID == 1 ? 2 : 1))" --json 2>/dev/null)"
BADSESS_RC=$?
set -e
[[ "$BADSESS_RC" == "3" ]] || fail "wrong session should yield Cache Reset"
echo "    wrong session id likewise -> Cache Reset (verified)"

# ---- 5. re-fetch after version change ---------------------------------------
banner "5. 换版后重新 Reset Query：取到包含 $P1 的新表"
RESET2="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" reset --json)"
S1="$(jq -r '.serial' <<<"$RESET2")"
CNT1="$(jq -r '.prefix_count' <<<"$RESET2")"
echo "$RESET2" | jq '{status, session_id, serial, prefix_count}'
echo "$RESET2" | jq -r '.prefixes[] | "    \(.prefix) maxLength=\(.max_length) AS\(.origin_asn)"'
[[ "$S1" == "$((S0 + 1))" ]] || fail "new reset serial should be S0+1"
[[ "$CNT1" == "$((CNT0 + 1))" ]] || fail "prefix count should grow by one"
jq -e --arg p "$P1" '.prefixes[] | select(.prefix == $p)' <<<"$RESET2" >/dev/null \
  || fail "new prefix $P1 missing from RTR table"

# ---- 6. new serial poll -> empty --------------------------------------------
banner "6. 用新 serial=$S1 发 Serial Query：空更新"
EMPTY2="$($PY "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" \
  serial "$S1" --session "$SID" --json)"
[[ "$(jq -r '.status' <<<"$EMPTY2")" == "empty_update" ]] || fail "expected empty_update"
echo "$EMPTY2" | jq '{status, serial, prefix_count}'

# ---- 7. async Serial Notify + automatic re-fetch ----------------------------
P2="$(pick_extra_prefix)" || fail "no free second demo prefix"
banner "7. 常驻 watch 连接 + 第二次启用（$P2）：异步 Serial Notify 后自动重新取表"
WLOG="$(mktemp)"
"$PY" "$CLIENT" --host "$RTR_HOST" --port "$RTR_PORT" \
  watch --duration 8 --refetch >"$WLOG" 2>&1 &
WPID=$!
for _ in $(seq 1 50); do
  grep -q "watching for Serial Notify" "$WLOG" 2>/dev/null && break
  sleep 0.1
done
sleep 0.5
ENABLE2="$(enable_additive_candidate "rtr-demo2" "$P2" "rtr-demo-$STAMP-b")"
S2="$(jq -r '.rtr.serial' <<<"$ENABLE2")"
echo "    [enable] second change advanced server serial to $S2"
wait "$WPID" || true
echo "    ---- rtr_client watch output ----"
sed 's/^/    /' "$WLOG"
echo "    ---------------------------------"
grep -q "Serial Notify: session=$SID newest serial=$S2" "$WLOG" \
  || fail "watch did not show coalesced Serial Notify serial=$S2"
grep -qF "$P2" "$WLOG" || fail "watch --refetch did not fetch $P2"
rm -f "$WLOG"

banner "ALL RTR DEMO CHECKS PASSED"
echo "  session=$SID  serial: $S0 -> $S1 -> $S2"
echo "  RTR endpoint: $RTR_HOST:$RTR_PORT (RFC 8210 v1)"
echo "  HTTP API:     $BASE_URL/docs"
