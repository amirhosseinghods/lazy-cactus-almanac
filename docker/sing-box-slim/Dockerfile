# syntax=docker/dockerfile:1.26

# A trimmed sing-box for V2Ray clients running inside RouterOS containers.
# The official image is ~90MB once extracted, which does not fit next to
# RouterOS on 128MB-flash routers. This build keeps only what the V2Ray
# gateway uses (QUIC for Hysteria2/TUIC, uTLS for REALITY, the Clash API to
# report the server urltest picked) and UPX-compresses the binary. TUN runs on
# the kernel stack, so gVisor is left out.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG SING_BOX_VERSION=1.14.3
RUN apk add --no-cache ca-certificates git upx
WORKDIR /src
RUN git clone --depth 1 --branch "v${SING_BOX_VERSION}" https://github.com/SagerNet/sing-box.git .
RUN set -eux; \
    if [ "$TARGETARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then export GOARM=${TARGETVARIANT#v}; fi; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath \
      -tags "with_quic,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0" \
      -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${SING_BOX_VERSION}' $(cat release/LDFLAGS) -s -w -buildid=" \
      -o /out/sing-box ./cmd/sing-box; \
    upx --best --lzma /out/sing-box

# busybox:musl provides the sh, mkdir, mknod and sysctl the gateway
# entrypoint (backend/pkg/proxylink/singbox.go) needs, in ~1.4MB.
FROM busybox:musl
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/sing-box /usr/local/bin/sing-box
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["sing-box"]
CMD ["run", "-c", "/etc/sing-box/config.json"]
