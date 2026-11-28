# The conformance harness as one image: the CLI (`eudi-pcaf`), both suites, the built-in adapters, and Chromium's
# headless shell for the DC API shim. Run it on the host network, so the system under test and the harness reach each
# other as with the bare CLI (running.md, "Docker image"):
#
#   docker run --rm --init --network host -v "$PWD:/work" ghcr.io/cre8/eudi-pcaf run --adapter ./my-adapter.ts --ics ics.yaml
#
# The working directory /work is where relative paths (adapter module, ICS, known findings, reports) resolve.
FROM node:22-bookworm-slim

ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true
RUN corepack enable

WORKDIR /app
# The lockfile first, so the dependency layer is rebuilt only when it changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm fetch
COPY . .
RUN pnpm install --offline --frozen-lockfile \
 && pnpm playwright:install --with-deps \
 && rm -rf /var/lib/apt/lists/* /root/.cache /root/.local/share/pnpm/store \
 && chmod -R a+rX /ms-playwright /app
# An adapter module outside the workspace imports `@eudi-pcaf/core`: Node finds it in /node_modules from any
# directory, including /work. Without a package.json of its own, such a module is an ES module (/package.json).
# `@rp-conformance/core`, the scope before the rename to eudi-pcaf, still resolves for adapters written against it.
RUN mkdir -p /node_modules/@eudi-pcaf /node_modules/@rp-conformance \
 && ln -s /app/packages/core /node_modules/@eudi-pcaf/core && ln -s /app/packages/core /node_modules/@rp-conformance/core \
 && echo '{"type":"module"}' > /package.json

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="eudi-pcaf" \
      org.opencontainers.image.description="Conformance harness for EUDI Wallet Relying Parties and Providers (PCAF)" \
      org.opencontainers.image.source="https://github.com/cre8/eudi-pcaf" \
      org.opencontainers.image.licenses="EUPL-1.2" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION

# Any user may run it (`--user $(id -u):$(id -g)`, so the reports belong to the caller); HOME must be writable.
ENV HOME=/tmp
WORKDIR /work
ENTRYPOINT ["node", "/app/packages/controller/bin/eudi-pcaf.mjs"]
CMD ["--help"]
