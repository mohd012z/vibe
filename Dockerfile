FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIBE_FILE_ROOT=/data

WORKDIR /app

RUN groupadd --system vibe && useradd --system --gid vibe --home /app vibe \
    && mkdir -p /data && chown -R vibe:vibe /app /data

COPY . /app
RUN python -m compileall -q tools

USER vibe
VOLUME ["/data"]

CMD ["python", "tools/vibebot_cli.py", "--serve"]
