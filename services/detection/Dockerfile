FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/detection/ ./services/detection/
COPY rules/ ./rules/
CMD ["python", "-m", "services.detection.main"]
