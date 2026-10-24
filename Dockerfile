FROM python:3.12-slim
WORKDIR /app
COPY evvp-backend/requirements.txt evvp-backend/requirements-optional.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt -r /app/requirements-optional.txt
COPY evvp-backend /app
RUN useradd -r -u 10001 evvp && mkdir -p /app/raw_data /app/data /app/logs && chown -R evvp /app
USER evvp
ENV PYTHONPATH=/app EVVP_HOST=0.0.0.0 EVVP_PORT=8000 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4).status==200 else 1)"
CMD ["python", "main.py"]
