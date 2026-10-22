FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN useradd --system --create-home vibecheck && mkdir -p /srv/data && chown vibecheck /srv/data
USER vibecheck

VOLUME ["/srv/data"]
EXPOSE 8000
# Use --proxy-headers se houver proxy reverso (para o rate limit ver o IP real).
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
