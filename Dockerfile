FROM python:3.13-slim

WORKDIR /app

COPY license_server.py admin.html ./

ENV PYTHONUNBUFFERED=1

CMD ["python", "license_server.py"]
