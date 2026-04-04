# Ansible operations for Agent Transponder.
# All targets run from the repo root; ansible commands cd into ansible/.

ANSIBLE_PLAYBOOK ?= site.yml
ENV              ?= dev

.PHONY: ansible-deps ansible-local ansible-deploy ansible-lint ansible-vault-edit ansible-check

## ansible-deps: Install required Ansible collections (community.crypto, ansible.posix).
ansible-deps:
	ansible-galaxy collection install -r ansible/requirements.yml

## ansible-local: Run local.yml against localhost (dev bootstrap, hardening disabled).
ansible-local:
	cd ansible && ansible-playbook local.yml --ask-become-pass

## ansible-deploy: Run site.yml against the specified ENV inventory (default: dev).
##   Usage: make ansible-deploy ENV=staging
ansible-deploy:
	cd ansible && ansible-playbook $(ANSIBLE_PLAYBOOK) -i inventory/$(ENV)

## ansible-lint: Lint all roles and playbooks with ansible-lint.
ansible-lint:
	cd ansible && ansible-lint roles/ site.yml local.yml

## ansible-vault-edit: Edit the encrypted vault file.
ansible-vault-edit:
	cd ansible && ansible-vault edit group_vars/all/vault.yml

## ansible-check: Dry-run site.yml with --check --diff (no changes applied).
##   Usage: make ansible-check ENV=staging
ansible-check:
	cd ansible && ansible-playbook $(ANSIBLE_PLAYBOOK) -i inventory/$(ENV) --check --diff

## build-all: Build all Go binaries to dist/ (required before ansible-deploy or ansible-local).
build-all:
	@mkdir -p dist
	@echo "Building ingester..."
	CGO_ENABLED=0 GOOS=linux go build -o dist/ingester ./cmd/ingestion
	@echo "Building analyzer..."
	CGO_ENABLED=0 GOOS=linux go build -o dist/analyzer ./cmd/analyzer
	@echo "Building metrics-exporter..."
	CGO_ENABLED=0 GOOS=linux go build -o dist/metrics-exporter ./cmd/exporter

## smoke-test: Run end-to-end smoke test against the dev inventory.
smoke-test:
	ansible-playbook ansible/smoke-test.yml -i ansible/inventory/dev/hosts.yml

## download-monitoring: Print download URLs for Prometheus and node_exporter binaries.
##   The Ansible roles download these automatically via get_url with checksum verification.
##   Use this target to manually pre-fetch tarballs or to retrieve checksums for defaults.
##   Usage: PROMETHEUS_VERSION=2.53.0 NODE_EXPORTER_VERSION=1.8.1 make download-monitoring
PROMETHEUS_VERSION     ?= 2.53.0
NODE_EXPORTER_VERSION  ?= 1.8.1

download-monitoring:
	@echo "Prometheus $(PROMETHEUS_VERSION):"
	@echo "  https://github.com/prometheus/prometheus/releases/download/v$(PROMETHEUS_VERSION)/prometheus-$(PROMETHEUS_VERSION).linux-amd64.tar.gz"
	@echo "  Checksum: https://github.com/prometheus/prometheus/releases/download/v$(PROMETHEUS_VERSION)/sha256sums.txt"
	@echo ""
	@echo "node_exporter $(NODE_EXPORTER_VERSION):"
	@echo "  https://github.com/prometheus/node_exporter/releases/download/v$(NODE_EXPORTER_VERSION)/node_exporter-$(NODE_EXPORTER_VERSION).linux-amd64.tar.gz"
	@echo "  Checksum: https://github.com/prometheus/node_exporter/releases/download/v$(NODE_EXPORTER_VERSION)/sha256sums.txt"
	@echo ""
	@echo "Update prometheus_checksum and node_exporter_checksum in the respective"
	@echo "role defaults/main.yml with the sha256 values from the checksum files above."
