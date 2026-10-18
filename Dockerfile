# syntax=docker/dockerfile:1
# Currawong container image. Build: docker build -t currawong:dev .
# The runtime stage is distroless (glibc, libgcc, CA certificates, no shell)
# and runs as the distroless nonroot user, 65532.

# The binaries link only libc, libm and libgcc_s (`readelf -d`). The cc image
# adds OpenSSL, libstdc++ and libgomp, about 8.5 MB that nothing loads, so the
# runtime is base-nossl plus libgcc_s and its package metadata from cc.
FROM gcr.io/distroless/cc-debian12:nonroot AS cc

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=cc /lib/ /cc/lib/
COPY --from=cc /var/lib/dpkg/status.d/ /cc/status.d/
RUN cargo build --release --locked -p currawongd -p currawong-parser-worker \
 && rustc -O -o target/release/currawong-healthcheck packaging/docker/healthcheck.rs \
 && strip target/release/currawongd target/release/currawong-parser-worker \
    target/release/currawong-healthcheck \
 && install -d -m 0750 -o 65532 -g 65532 /out/var/spool/currawong /out/var/lib/currawong \
 && multiarch=$(gcc -print-multiarch) \
 && install -D -m 0644 "/cc/lib/$multiarch/libgcc_s.so.1" "/out/rt/lib/$multiarch/libgcc_s.so.1" \
 && install -D -m 0644 -t /out/rt/var/lib/dpkg/status.d \
    /cc/status.d/libgcc-s1 /cc/status.d/libgcc-s1.md5sums \
    /cc/status.d/gcc-12-base /cc/status.d/gcc-12-base.md5sums

FROM gcr.io/distroless/base-nossl-debian12:nonroot
COPY --from=build /out/rt/ /
COPY --from=cc /usr/share/doc/gcc-12-base/ /usr/share/doc/gcc-12-base/
# currawongd looks for the parser worker next to its own executable.
COPY --from=build /src/target/release/currawongd /usr/bin/currawongd
COPY --from=build /src/target/release/currawong-parser-worker /usr/bin/currawong-parser-worker
COPY --from=build /src/target/release/currawong-healthcheck /usr/bin/currawong-healthcheck
COPY --from=build --chown=65532:65532 /out/var/ /var/
# Example config as a starting point. Mount your own at /etc/currawong and
# provide cert.pem and key.pem there, or the STARTTLS listeners will not start.
COPY config/currawong.example.toml /etc/currawong/currawong.toml
# Bind metrics, /healthz and /readyz on all interfaces so the host and
# Kubernetes probes can reach them. The HEALTHCHECK uses loopback.
ENV CURRAWONG_METRICS__LISTEN=0.0.0.0:9090
USER 65532:65532
# 25 inbound, 587 and 465 submission, 8443 admin UI (later milestone), 9090 metrics.
# Ports below 1024 bind as non-root because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in the container network namespace.
EXPOSE 25 587 465 8443 9090
VOLUME ["/var/spool/currawong", "/var/lib/currawong"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/currawong-healthcheck", "127.0.0.1:9090"]
ENTRYPOINT ["/usr/bin/currawongd"]
CMD ["--config", "/etc/currawong/currawong.toml"]
