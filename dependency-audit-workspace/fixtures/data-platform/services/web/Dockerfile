FROM python:3.8-slim-bullseye
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["gunicorn", "portal.wsgi:application", "--bind", "0.0.0.0:8000"]
