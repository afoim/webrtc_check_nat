FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir aiohttp

COPY netcheck.py .

EXPOSE 8080 3478/udp 3479/udp

ENTRYPOINT ["python", "netcheck.py"]