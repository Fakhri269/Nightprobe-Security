FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY mysite/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the django project
COPY mysite/ .

# Create SQLite database and run migrations
RUN python manage.py migrate

# Hugging Face Spaces requires apps to run on port 7860
EXPOSE 7860

# Run Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:7860", "mysite.wsgi:application"]
