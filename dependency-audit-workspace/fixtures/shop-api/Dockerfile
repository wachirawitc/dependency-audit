FROM node:14.21.3-alpine3.17
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public
COPY views ./views
EXPOSE 3000
CMD ["node", "src/server.js"]
