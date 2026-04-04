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

## Note: prometheus and node_exporter are installed via apt (Ubuntu 24.04 universe).
## No tarball downloads or checksums required — apt handles versioning.
