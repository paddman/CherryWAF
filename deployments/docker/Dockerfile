# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/cherrywaf ./cmd/cherrywaf && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w" -o /out/cherrywafctl ./cmd/cherrywafctl

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 cherrywaf \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin cherrywaf
COPY --from=build /out/cherrywaf /usr/local/bin/cherrywaf
COPY --from=build /out/cherrywafctl /usr/local/bin/cherrywafctl
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/cherrywaf"]
CMD ["serve", "--config", "/etc/cherrywaf/cherrywaf.json"]
