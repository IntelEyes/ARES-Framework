FROM python:3.11-slim

WORKDIR /app

COPY services/mismatch_injector/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/mismatch_injector/ /app/services/mismatch_injector/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/mismatch_injector/main.py"]
