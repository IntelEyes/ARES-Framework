FROM python:3.11-slim

WORKDIR /app

COPY services/agents/langgraph_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/agents/langgraph_agent/ /app/services/agents/langgraph_agent/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/agents/langgraph_agent/main.py"]
