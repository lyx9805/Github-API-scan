#!/bin/bash
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== GitHub Secret Scanner Pro - Docker ===${NC}"

# 检查 GitHub Token
if [ -z "$GITHUB_TOKENS" ]; then
    echo -e "${RED}错误: 未设置 GITHUB_TOKENS 环境变量${NC}"
    echo "请在 .env 文件或 docker-compose.yml 中配置 GitHub Token"
    echo "获取方式: https://github.com/settings/tokens"
    exit 1
fi

# 检测 Token 数量
TOKEN_COUNT=$(echo "$GITHUB_TOKENS" | tr ',' '\n' | wc -l)
echo -e "${GREEN}已配置 ${TOKEN_COUNT} 个 GitHub Token${NC}"

# 显示代理配置
if [ -n "$PROXY_URL" ]; then
    echo -e "${YELLOW}代理: ${PROXY_URL}${NC}"
else
    echo -e "${YELLOW}代理: 未配置（直连模式）${NC}"
fi

# 构建参数
ARGS="--db /app/data/leaked_keys.db"

# 扫描源配置
if [ "${ENABLE_ALL_SOURCES}" = "true" ]; then
    ARGS="$ARGS --all-sources"
else
    [ "${ENABLE_GIST}" = "true" ] && ARGS="$ARGS --gist"
    [ "${ENABLE_GITLAB}" = "true" ] && ARGS="$ARGS --gitlab"
    [ "${ENABLE_PASTEBIN}" = "true" ] && ARGS="$ARGS --pastebin"
    [ "${ENABLE_SEARCHCODE}" = "true" ] && ARGS="$ARGS --searchcode"
    [ "${ENABLE_REALTIME}" = "true" ] && ARGS="$ARGS --realtime"
    [ "${ENABLE_SOURCEGRAPH}" = "true" ] && ARGS="$ARGS --sourcegraph"
fi

# 禁用性能监控（可选）
[ "${DISABLE_MONITOR}" = "true" ] && ARGS="$ARGS --no-monitor"
[ "${DISABLE_CACHE}" = "true" ] && ARGS="$ARGS --no-cache"

# 选择扫描器版本
SCANNER="${SCANNER_VERSION:-main_v2.2.py}"

echo -e "${GREEN}启动扫描器: ${SCANNER}${NC}"
echo -e "${GREEN}参数: ${ARGS}${NC}"
echo ""

# 启动扫描器
LOG_PATH="${SCANNER_LOG_PATH:-/app/output/scanner.log}"
mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH"
exec python "$SCANNER" $ARGS "$@" 2>&1 | tee -a "$LOG_PATH"
