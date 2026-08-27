FROM node:20-slim

# scanner binaries (nmap baked in; nuclei optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils ca-certificates iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .

# data volume for users.json + scans.json
VOLUME ["/app/data"]
EXPOSE 8888

# pm2-runtime keeps it as a single foreground process (container-friendly)
RUN npm install -g pm2
CMD ["pm2-runtime", "start", "ecosystem.config.js"]
