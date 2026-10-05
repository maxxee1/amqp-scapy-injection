FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --uid 1000 app
USER app

COPY --chown=app:app Insaneado.py .

CMD ["python", "-u", "Insaneado.py"]
