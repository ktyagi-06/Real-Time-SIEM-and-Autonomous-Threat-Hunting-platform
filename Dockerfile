FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SIEM_DB_PATH=/data/siem.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY siem_hunter ./siem_hunter
RUN useradd --create-home --uid 10001 siem && mkdir /data && chown siem /data
USER siem
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
CMD ["python", "-m", "siem_hunter", "serve", "--host", "0.0.0.0", "--port", "8000"]
