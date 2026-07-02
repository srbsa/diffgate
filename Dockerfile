FROM node:24-bookworm-slim AS build
WORKDIR /app
# tree-sitter-* deps compile native bindings via node-gyp at install time
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
  && apt-get purge -y --auto-remove python3 make g++
COPY --from=build /app/dist ./dist
COPY --from=build /app/mock_project ./mock_project

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["mcp"]
