FROM python:3.11-slim

WORKDIR /app

COPY services/dataset_writer/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ /app/shared/
COPY services/dataset_writer/ /app/services/dataset_writer/

ENV SIMULATION_MODE=false
ENV PYTHONPATH=/app

CMD ["python", "services/dataset_writer/main.py"]
