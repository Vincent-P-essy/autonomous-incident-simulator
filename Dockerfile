FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN groupadd --gid 65532 simulator \
    && useradd --uid 65532 --gid simulator --no-create-home --shell /usr/sbin/nologin simulator

COPY --chown=65532:65532 src/ ./src/
COPY --chown=65532:65532 examples/ ./examples/
COPY --chown=65532:65532 schemas/ ./schemas/

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=2).read()"]

CMD ["python", "-m", "incident_simulator", "serve", "--host", "0.0.0.0", "--port", "8080", "--scenario-dir", "examples"]
