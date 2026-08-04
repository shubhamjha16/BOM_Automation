# syntax=docker/dockerfile:1.7
#
# Console image. Multi-stage: yarn builds, nginx serves. The runtime stage keeps
# no node_modules and no toolchain — the production image should contain static
# files and a web server, nothing that could execute a build script.

FROM node:22-slim AS build

WORKDIR /repo

# Workspace manifests first, for a cacheable dependency layer. The root
# package.json defines the yarn workspaces, so it has to come along.
COPY package.json yarn.lock ./
COPY frontend/package.json frontend/
COPY packages/api-types/package.json packages/api-types/
RUN yarn install --frozen-lockfile

COPY frontend/ frontend/
COPY packages/ packages/

# Vite inlines env at build time, so the API URL is baked into the bundle here
# rather than read at runtime. It is public by definition — never a secret.
ARG VITE_API_BASE_URL=http://localhost:8005/api/v1
ARG VITE_SENTRY_DSN=
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_SENTRY_DSN=$VITE_SENTRY_DSN

RUN yarn workspace @bom-factory/frontend build


FROM nginx:1.27-alpine AS runtime

COPY --from=build /repo/frontend/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://localhost/ >/dev/null || exit 1
