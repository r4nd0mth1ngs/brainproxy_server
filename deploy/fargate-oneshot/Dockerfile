# Example: the stateless `ci` task's image. It is the server image (docker/server.Dockerfile, built
# with a brainproxy CLI of 0.5.2 or later) plus the AWS CLI, jq, this folder's entrypoint and a
# pinned rules bundle. Build from the repository root:
#
#   docker buildx build --platform linux/amd64 -f deploy/fargate-oneshot/Dockerfile \
#     --build-arg BASE=111122223333.dkr.ecr.eu-west-1.amazonaws.com/brainproxy-server:TAG \
#     --build-arg ZAP_REF=<40-character zap-extensions commit> \
#     --build-arg NUCLEI_REF=<40-character nuclei-templates commit> \
#     -t 111122223333.dkr.ecr.eu-west-1.amazonaws.com/brainproxy-ci:TAG --push .
#
# The bundle is fetched here, at build time, so the scan task never needs GitHub in its egress.
# Rebuild on a schedule to refresh it (README.md, "Rules bundle").

ARG BASE=111122223333.dkr.ecr.eu-west-1.amazonaws.com/brainproxy-server:TAG

FROM ${BASE}
ARG ZAP_REF
ARG NUCLEI_REF
USER 0:0
RUN apk add --no-cache aws-cli jq \
    && install -d -o 1000 -g 1000 /opt/brainproxy-home
COPY --chmod=0755 deploy/fargate-oneshot/entrypoint.sh /usr/local/bin/ci-entrypoint
# The system scope: the network every run of this image may reach, fixed in the image (never in
# the config bucket). `ci` hands BRAINPROXY_SYSTEM_SCOPE to the CLI; without it, `ci` would use
# the target's own scope (and say so in run.json), which whoever can write target.json controls.
# The entrypoint refuses to start without it. Edit system-scope.json (the `engagement show`
# shape: name, include, exclude) before building. The task definition sets the same path.
COPY --chmod=0644 deploy/fargate-oneshot/system-scope.json /etc/brainproxy-ci/system-scope.json
ENV BRAINPROXY_SYSTEM_SCOPE=/etc/brainproxy-ci/system-scope.json
USER 1000:1000
ENV BRAINPROXY_HOME=/opt/brainproxy-home
RUN set -eu; \
    : "${ZAP_REF:?pass --build-arg ZAP_REF}" "${NUCLEI_REF:?pass --build-arg NUCLEI_REF}"; \
    brainproxy scan data update --ref "$ZAP_REF"; \
    brainproxy checks update --ref "$NUCLEI_REF"; \
    brainproxy checks update --source brainproxy; \
    brainproxy scan data status; \
    brainproxy checks status
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ci-entrypoint"]
CMD []
