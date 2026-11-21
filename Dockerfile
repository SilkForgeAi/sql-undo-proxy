FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY reverse_proxy ./reverse_proxy

EXPOSE 5433 3307 8080
ENTRYPOINT ["python", "-m", "reverse_proxy.cli"]
