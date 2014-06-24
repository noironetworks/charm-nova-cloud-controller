#!/usr/bin/make
PYTHON := /usr/bin/env python

lint:
	@flake8 --exclude hooks/charmhelpers hooks unit_tests
	@charm proof

test:
	@echo Starting tests...
	@$(PYTHON) /usr/bin/nosetests --nologcapture --with-coverage  unit_tests

sync:
	@charm-helper-sync -c charm-helpers-hooks.yaml
	@charm-helper-sync -c charm-helpers-tests.yaml

publish: lint test
	bzr push lp:charms/nova-cloud-controller
	bzr push lp:charms/trusty/nova-cloud-controller
