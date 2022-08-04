FROM ghcr.io/dexidp/dex:v2.33.0
ENV DEX_FRONTEND_DIR=/srv/dex/web
COPY --chown=root:root pkg/web /srv/dex/web