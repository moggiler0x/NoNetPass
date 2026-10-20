FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY nonetpass ./nonetpass
RUN pip install --no-cache-dir . && useradd -r nonetpass && mkdir /data && chown nonetpass /data
USER nonetpass
ENV NONETPASS_LOG_PATH=/data/sessions.jsonl
EXPOSE 8080
CMD ["nonetpass", "--port", "8080"]
