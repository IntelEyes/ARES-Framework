FROM python:3.11-slim

WORKDIR /app

COPY services/anomaly_monitor/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/anomaly_monitor/ /app/services/anomaly_monitor/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/anomaly_monitor/main.py"]
