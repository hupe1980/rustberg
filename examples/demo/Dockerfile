# The narrator for the five-minute proof. Builds nothing from the catalog: it is a client.
FROM python:3.13-slim
RUN pip install --no-cache-dir "pyiceberg[pyarrow]==0.10.0" "httpx==0.28.1"
COPY demo.py /demo.py
ENTRYPOINT ["python", "/demo.py"]
