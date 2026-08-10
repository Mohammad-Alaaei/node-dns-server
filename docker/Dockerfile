# Production image for the DNS server (Node + Alpine)
FROM node:22-alpine

RUN apk add --no-cache tini

WORKDIR /app

# Install production dependencies + sequelize-cli (needed for runtime migrations/seeds)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
 && npm install sequelize-cli --no-save \
 && npm cache clean --force

# App source (node_modules excluded via .dockerignore)
COPY . .

# Ensure runtime directories + executable entrypoint
RUN mkdir -p /app/logs /app/data \
 && chmod +x /app/docker/entrypoint.sh

ENV NODE_ENV=production
ENV LOG_DIR=/app/logs

EXPOSE 53/udp 3000

# Run as root so we can bind :53 and write to mounted volumes without extra chown logic.
# tini is used as PID 1 for proper signal handling.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/app/docker/entrypoint.sh"]
