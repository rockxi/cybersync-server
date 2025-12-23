FROM python:3.13-slim

WORKDIR /app

RUN apt-get update
RUN apt-get install -y libldap2-dev libsasl2-dev gcc

RUN pip install uv

COPY pyproject.toml uv.lock ./

RUN uv sync

COPY . .

ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uv", "run", "--no-sync", "uvicorn", "main:app", "--host", "0.0.0.0"]

