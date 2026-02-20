# Use the official Bun image (Alpine for a smaller footprint)
FROM oven/bun:1.1-alpine AS base
WORKDIR /usr/src/app

# Install necessary system dependencies for Prisma/SSL
# Alpine needs these to run the Prisma engine binary
RUN apk add --no-cache openssl libssl3 libcrypto3

# Install dependencies (using a cache-friendly approach)
COPY package.json bun.lockb* ./ 
RUN bun install --frozen-lockfile

# Copy the rest of the application
COPY . .

# Generate Prisma Client
# Bun can run 'prisma' directly if it's in your dependencies
RUN bunx prisma generate

# Expose the dev server port
EXPOSE 4000

# Set environment to development
ENV NODE_ENV=development

# Start the dev server
CMD ["bun", "run", "dev"]