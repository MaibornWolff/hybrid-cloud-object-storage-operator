FROM python:3.11-slim

RUN mkdir /operator
WORKDIR /operator
# Install python dependencies
COPY requirements.txt /operator/requirements.txt
RUN pip install -r /operator/requirements.txt && rm -rf /root/.cache/pip
# Copy operator code
COPY main.py /operator/
COPY hybridcloud /operator/hybridcloud
# Switch to extra user
RUN useradd -M -U -u 1000 hybridcloud && chown -R hybridcloud:hybridcloud /operator
USER 1000:1000
CMD ["kopf", "run", "--liveness=http://0.0.0.0:8080/healthz", "main.py", "-A"]
