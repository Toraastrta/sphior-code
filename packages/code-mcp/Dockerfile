# SPHIOR CODE MCP server (stdio), built from this directory.
# Local mode: no account or API key. The workspace to scan is mounted read-only at /workspace.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json npm-shrinkwrap.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY bin ./bin
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:22-slim
ENV NODE_ENV=production \
    SPHIOR_WORKSPACE=/workspace
WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/bin ./bin
USER node
ENTRYPOINT ["node", "/app/bin/sphior-code-mcp.js"]
