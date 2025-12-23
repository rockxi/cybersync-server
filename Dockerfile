FROM python:3.13-slim

WORKDIR /app

RUN apt-get update

RUN pip install uv

COPY pyproject.toml uv.lock ./

RUN uv sync

COPY . .

EXPOSE 8000

CMD ["uv", "run", "main.py"]

