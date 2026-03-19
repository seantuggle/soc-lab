FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tools/ ./tools/
COPY services/attacker/ ./services/attacker/
COPY shared/ ./shared/
CMD ["uvicorn", "services.attacker.main:app", "--host", "0.0.0.0", "--port", "8090"]
