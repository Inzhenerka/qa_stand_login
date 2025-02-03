FROM python:3.11.10-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.5.24 /uv /uvx /bin/

WORKDIR /app

COPY ./src /app/src
COPY ./app_prod.py /app/
COPY ./pyproject.toml /app/
COPY ./uv.lock /app/

RUN uv sync --frozen --no-dev --no-cache

EXPOSE 80

CMD ["uv", "run", "app_prod.py"]
