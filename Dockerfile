FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY nonetpass ./nonetpass
RUN pip install --no-cache-dir . && useradd -r nonetpass && mkdir /data && chown nonetpass /data
USER nonetpass
ENV NONETPASS_LOG_PATH=/data/sessions.jsonl \
    NONETPASS_STATE_PATH=/data/state.json \
    NONETPASS_DRIVER_OPT_STATE_FILE=/data/keenetic-state.json
VOLUME /data
# 8080: портал, админ-панель, /metrics; 5514/udp: syslog роутера для DNS-детекции.
EXPOSE 8080 5514/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
CMD ["nonetpass", "--port", "8080"]
