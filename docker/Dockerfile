FROM python:3.12-slim

WORKDIR /app
COPY . .

CMD ["python", "dashboard/app.py", "--log", "data/nginx-web-attacks.log", "--out-dir", "reports"]
