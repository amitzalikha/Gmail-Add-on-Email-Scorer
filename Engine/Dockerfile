FROM python:3.10-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Install system dependencies required for building some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies 
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Set an environment variable so Python treats the /app directory as the root for imports
ENV PYTHONPATH=/app

# the container listens on port 8000 
EXPOSE 8000

CMD ["uvicorn", "Engine.main:app", "--host", "0.0.0.0", "--port", "8000"]