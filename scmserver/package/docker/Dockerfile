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

# The image has no /tmp (FROM scratch). Temporary files, such as the
# unpacked copy `scmserver backup verify` checks, go in the data volume.
ENV TMPDIR=/var/lib/openscm

EXPOSE 8000

VOLUME ["/etc/openscm", "/var/lib/openscm"]

CMD ["/usr/bin/scmserver"]
