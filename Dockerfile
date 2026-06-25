FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖（编译 cchardet 等需要）
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ docker.io && \
    rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY . .

# 设置入口脚本权限
RUN chmod +x entrypoint.sh

# 创建数据目录
RUN mkdir -p /app/data /app/output

# 设置环境变量默认值
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/app/data/leaked_keys.db

# 健康检查（检查数据库文件是否可访问）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import sqlite3; conn = sqlite3.connect('${DB_PATH}'); conn.close()" || exit 1

# 入口点
ENTRYPOINT ["./entrypoint.sh"]

# 默认参数（可通过 docker run 末尾参数覆盖）
CMD []
