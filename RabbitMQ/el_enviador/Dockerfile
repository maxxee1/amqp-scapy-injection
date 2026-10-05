FROM python:3.11-slim

# Dependencias pinneadas (reproducibilidad)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ejecutar como usuario sin privilegios (mínimo privilegio)
RUN useradd --create-home --uid 1000 app
USER app

COPY --chown=app:app Insaneador.py .

# -u = salida sin buffer para ver los logs en tiempo real
CMD ["python", "-u", "Insaneador.py"]
