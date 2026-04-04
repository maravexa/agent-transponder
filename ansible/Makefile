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
