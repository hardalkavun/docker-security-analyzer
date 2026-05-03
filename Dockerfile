FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY . .
USER appuser

CMD ["python", "app.py"]
