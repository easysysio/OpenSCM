FROM scratch

ARG VERSION

LABEL org.opencontainers.image.title="OpenSCM Server" \
      org.opencontainers.image.description="Privacy-first security compliance management" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="OpenSCM" \
      org.opencontainers.image.url="https://openscm.io" \
      org.opencontainers.image.documentation="https://openscm.io" \
      org.opencontainers.image.source="https://github.com/easysysio/OpenSCM" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2"

# Binary is staged at the build context root by the CI workflow
COPY scmserver /usr/bin/scmserver

# The server runs as user 65532 ("nonroot"), not root (1.1.0). FROM scratch has
# no shell to mkdir/chown, so the CI workflow stages the two empty data folders
# under rootfs/ and they are copied in owned by that user. A new named volume
# takes this ownership; one made by an older image still belongs to root, and
# the server stops at startup with the chown command that fixes it.
COPY --chown=65532:65532 rootfs/ /
USER 65532:65532

# The image has no /tmp (FROM scratch). Temporary files, such as the
# unpacked copy `scmserver backup verify` checks, go in the data volume.
ENV TMPDIR=/var/lib/openscm

EXPOSE 8000

VOLUME ["/etc/openscm", "/var/lib/openscm"]

CMD ["/usr/bin/scmserver"]
