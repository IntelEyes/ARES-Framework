FROM python:3.11-slim

WORKDIR /app

COPY services/agents/autogen_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/agents/autogen_agent/ /app/services/agents/autogen_agent/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/agents/autogen_agent/main.py"]
