FROM python:3.11-slim

WORKDIR /app

COPY services/agents/rulebased_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/agents/rulebased_agent/ /app/services/agents/rulebased_agent/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/agents/rulebased_agent/main.py"]
