FROM node:20-bookworm-slim

WORKDIR /app

# Install build tools for native modules
RUN apt-get update -qq && apt-get install -y -qq python3 make g++ sqlite3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy ALL backend source (node_modules excluded by .dockerignore)
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Install dependencies - this creates node_modules INSIDE the container
RUN cd backend && npm install --omit=dev && npm rebuild

# Create uploads directory
RUN mkdir -p /app/backend/uploads

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/api/stats || exit 1

# Start
WORKDIR /app/backend
CMD ["node", "index.js"]
