FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY authpass ./authpass
RUN pip install --no-cache-dir . && useradd -r authpass && mkdir /data && chown authpass /data
USER authpass
ENV AUTHPASS_LOG_PATH=/data/sessions.jsonl
EXPOSE 8080
CMD ["authpass", "--port", "8080"]
