FROM python:3.11-slim

WORKDIR /app

# Dependencies installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App kopieren
COPY . .

# Bot starten
CMD ["python", "bot.py"]
