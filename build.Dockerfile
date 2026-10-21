FROM ghcr.io/formancehq/base:26.04
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/auth /usr/bin/auth
ENV OTEL_SERVICE_NAME auth
ENTRYPOINT ["/usr/bin/auth"]
CMD ["serve"]
