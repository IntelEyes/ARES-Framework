FROM python:3.11-slim

WORKDIR /app

COPY services/scenario_engine/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/scenario_engine/ /app/services/scenario_engine/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/scenario_engine/main.py"]
