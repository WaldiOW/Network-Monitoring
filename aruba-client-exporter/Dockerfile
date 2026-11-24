FROM python:3.12-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends snmp \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY client_exporter.py .

EXPOSE 9118
CMD ["python", "client_exporter.py"]
