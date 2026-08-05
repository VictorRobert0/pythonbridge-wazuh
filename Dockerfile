FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /srv/app/

RUN mkdir -p /data

WORKDIR /srv/app

EXPOSE 8000

CMD ["python", "main.py"]
