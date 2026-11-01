FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home analyst && mkdir /db && chown analyst:analyst /db
COPY backend backend
COPY rules rules
COPY tests tests
COPY pytest.ini .
COPY docs docs
ENV PYTHONPATH=/app PYTEST_ADDOPTS="-o cache_dir=/tmp/killchain-pytest-cache"
USER analyst
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
