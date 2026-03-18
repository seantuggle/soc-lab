FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY tools/ ./tools/
WORKDIR /app
ENTRYPOINT ["python", "tools/generate_events.py"]
