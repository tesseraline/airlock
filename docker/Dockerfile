# The gateway image: the package and its one dependency, installed by hash; no shell tools added; runs as a
# non-root user on a read-only filesystem (set by the runtime). Build from the repository root after `uv build`:
#   uv export --no-dev --no-emit-project --format requirements-txt > docker/requirements.txt
#   uv build --wheel && docker build -f docker/Dockerfile -t airlock-gateway .
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY docker/requirements.txt /tmp/requirements.txt
COPY dist/ /tmp/dist/
RUN pip install --require-hashes -r /tmp/requirements.txt \
 && pip install --no-deps /tmp/dist/tesseraline_airlock-*.whl \
 && rm -rf /tmp/requirements.txt /tmp/dist \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin airlock

USER 10001
EXPOSE 8443
ENTRYPOINT ["airlock"]
CMD ["serve"]
