FROM --platform=${BUILDPLATFORM:-linux/amd64} alpine:3.21.3

COPY ionscale /usr/local/bin/ionscale

RUN addgroup -S ionscale && adduser -S -G ionscale ionscale \
    && mkdir -p /data/ionscale \
    && chown -R ionscale:ionscale /data/ionscale
WORKDIR /data/ionscale

USER ionscale

ENTRYPOINT ["/usr/local/bin/ionscale"]
