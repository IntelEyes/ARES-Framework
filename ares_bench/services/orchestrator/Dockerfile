FROM python:3.11-slim

WORKDIR /app

COPY services/orchestrator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/orchestrator/ /app/services/orchestrator/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/orchestrator/main.py"]
