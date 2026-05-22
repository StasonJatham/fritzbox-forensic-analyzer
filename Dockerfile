FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FRITZBOX_ANALYSIS_DB=/app/data/fritzbox-analysis.sqlite3

WORKDIR /app

COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY fritzbox_*.py ./
COPY static ./static

RUN pip install --no-cache-dir .

RUN mkdir -p /app/data

EXPOSE 8765

CMD ["python", "fritzbox_wifi_dashboard.py", "--host", "0.0.0.0", "--port", "8765"]
