# Base images are pinned by tag only. For production builds pin them by
# digest (FROM image:tag@sha256:...) after checking the digest yourself;
# the digests are deliberately not hard-coded here.
# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
# .dockerignore keeps data/, tokens.json, trove.json and .env out of the context.
COPY . .
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X trove.Version=${VERSION}" -o /out/trove ./cmd/trove

# Runtime stage: Alpine with git, non-root, works with a read-only root fs
FROM alpine:3.20
RUN apk add --no-cache git ca-certificates \
 && addgroup -S -g 10001 trove \
 && adduser -S -D -H -u 10001 -G trove trove \
 && mkdir -p /data /config \
 && chown trove:trove /data
COPY --from=build /out/trove /usr/local/bin/trove
USER 10001:10001
ENV HOME=/data TROVE_CONFIG=/config/trove.json
VOLUME ["/data"]
EXPOSE 8470
ENTRYPOINT ["/usr/local/bin/trove"]
CMD ["serve"]
