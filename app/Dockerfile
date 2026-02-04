# syntax=docker/dockerfile:1

ARG NODE_VERSION=24.13.0
FROM node:${NODE_VERSION}-alpine

# Nu setăm NODE_ENV=production pentru dev
ENV NODE_ENV=development

# Install Bun globally and OpenSSL
RUN npm install -g bun && \
    apk add --no-cache openssl libssl3 libcrypto3

WORKDIR /usr/src/app

# Copy deps first (cache friendly)
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy all source files
COPY . .

# Generate Prisma Client for Linux
RUN npx prisma generate

# Expose port for dev server
EXPOSE 4000

# Run dev server
CMD ["bun", "run", "dev"]
