FROM python:3.10-slim

WORKDIR /app

# התקנת כלים בסיסיים
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# העתקת הדרישות והתקנה
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# העתקת כל הפרויקט (כולל תיקיית Engine)
COPY . .

# הגדרת משתנה סביבה כדי שפייתון יכיר את התיקייה הנוכחית כשורש
ENV PYTHONPATH=/app

EXPOSE 8000

# הרצה של uvicorn מתוך תיקיית Engine
CMD ["uvicorn", "Engine.main:app", "--host", "0.0.0.0", "--port", "8000"]