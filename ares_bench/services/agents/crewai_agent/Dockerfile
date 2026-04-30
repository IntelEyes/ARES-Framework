FROM python:3.11-slim

WORKDIR /app

COPY services/agents/crewai_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/agents/crewai_agent/ /app/services/agents/crewai_agent/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/agents/crewai_agent/main.py"]
