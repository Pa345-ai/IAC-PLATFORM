FROM node:20-alpine

# Create a non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S node -u 1001

WORKDIR /app

# Change ownership of the working directory
RUN chown -R node:nodejs /app

# Switch to non-root user
USER node

COPY package*.json ./
RUN npm ci --only=production

COPY app.js ./

EXPOSE 3000

CMD ["node", "app.js"]
