#!/bin/sh
# Privileged deployment hook: takes no arguments and makes no decisions, so the
# CI account can be granted this one fixed command via sudo instead of docker
# group membership (root-equivalent on this host).
#
# Install manually as root; the copy in the source tree is inert until then:
#   install -o root -g root -m 755 deploy/triage-deploy.sh \
#           /usr/local/sbin/deploy-wazuh-llm-triage
#
# Grant (/etc/sudoers.d/jenkins-deploy, mode 0440):
#   deploy ALL=(root) NOPASSWD: /usr/local/sbin/deploy-wazuh-llm-triage
set -eu

APP_DIR=/opt/wazuh-llm-triage

cd "$APP_DIR"

docker compose up -d --build triage

# populate_db.py recreates the collection, so re-indexing also drops removed chunks.
docker compose run --rm populate
