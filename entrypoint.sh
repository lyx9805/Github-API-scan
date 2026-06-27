#!/bin/sh
set -e

# 棰滆壊杈撳嚭
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== GitHub Secret Scanner Pro - Docker ===${NC}"

# 妫€鏌?GitHub Token
if [ -z "$GITHUB_TOKENS" ]; then
    echo -e "${RED}閿欒: 鏈缃?GITHUB_TOKENS 鐜鍙橀噺${NC}"
    echo "璇峰湪 .env 鏂囦欢鎴?docker-compose.yml 涓厤缃?GitHub Token"
    echo "鑾峰彇鏂瑰紡: https://github.com/settings/tokens"
    exit 1
fi

# 妫€娴?Token 鏁伴噺
TOKEN_COUNT=$(echo "$GITHUB_TOKENS" | tr ',' '\n' | wc -l)
echo -e "${GREEN}宸查厤缃?${TOKEN_COUNT} 涓?GitHub Token${NC}"

# 鏄剧ず浠ｇ悊閰嶇疆
if [ -n "$PROXY_URL" ]; then
    echo -e "${YELLOW}浠ｇ悊: ${PROXY_URL}${NC}"
else
    echo -e "${YELLOW}浠ｇ悊: 鏈厤缃紙鐩磋繛妯″紡锛?{NC}"
fi

# 鏋勫缓鍙傛暟
ARGS="--db /app/data/leaked_keys.db"

# 鎵弿婧愰厤缃?
if [ "${ENABLE_ALL_SOURCES}" = "true" ]; then
    ARGS="$ARGS --all-sources"
else
    [ "${ENABLE_GIST}" = "true" ] && ARGS="$ARGS --gist"
    [ "${ENABLE_GITLAB}" = "true" ] && ARGS="$ARGS --gitlab"
    [ "${ENABLE_PASTEBIN}" = "true" ] && ARGS="$ARGS --pastebin"
    [ "${ENABLE_SEARCHCODE}" = "true" ] && ARGS="$ARGS --searchcode"
    [ "${ENABLE_REALTIME}" = "true" ] && ARGS="$ARGS --realtime"
    [ "${ENABLE_SOURCEGRAPH}" = "true" ] && ARGS="$ARGS --sourcegraph"
    [ "${ENABLE_GIT_CLONE}" = "true" ] && ARGS="$ARGS --git"
fi

[ -n "${GIT_CLONE_DIR}" ] && ARGS="$ARGS --git-clone-dir ${GIT_CLONE_DIR}"

# 绂佺敤鎬ц兘鐩戞帶锛堝彲閫夛級
[ "${DISABLE_MONITOR}" = "true" ] && ARGS="$ARGS --no-monitor"
[ "${DISABLE_CACHE}" = "true" ] && ARGS="$ARGS --no-cache"

# 閫夋嫨鎵弿鍣ㄧ増鏈?
SCANNER="${SCANNER_VERSION:-main.py}"

echo -e "${GREEN}鍚姩鎵弿鍣? ${SCANNER}${NC}"
echo -e "${GREEN}鍙傛暟: ${ARGS}${NC}"
echo ""

# 鍚姩鎵弿鍣?
LOG_PATH="${SCANNER_LOG_PATH:-/app/output/scanner.log}"
mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH"
exec python "$SCANNER" $ARGS "$@" 2>&1 | tee -a "$LOG_PATH"