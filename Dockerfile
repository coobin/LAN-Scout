# LAN Scout — discovery dashboard for your local network.
# nmap is the only system dependency; the app itself is pure stdlib Python.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Bind to all interfaces inside the container and keep the DB on a volume so
# settings/history survive restarts.
ENV LANSCOUT_HOST=0.0.0.0 \
    LANSCOUT_PORT=8770 \
    LANSCOUT_DB=/data/lanscout.db

VOLUME ["/data"]
EXPOSE 8770

CMD ["python3", "server.py"]
