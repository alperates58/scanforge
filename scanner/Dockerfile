FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN adduser -D -u 1000 scanforge

COPY worker.py contracts/mock_scan_result.json ./

RUN mkdir -p /data && chown -R scanforge:scanforge /app /data

USER scanforge

CMD ["python", "worker.py"]
