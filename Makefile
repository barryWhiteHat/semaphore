ROOT_DIR := $(shell dirname $(realpath $(MAKEFILE_LIST)))

PYTHON ?= python3
NAME ?= ethsnarks
NPM ?= npm
GANACHE ?= $(ROOT_DIR)/node_modules/.bin/ganache-cli
TRUFFLE ?= $(ROOT_DIR)/node_modules/.bin/truffle

COVERAGE = $(PYTHON) -mcoverage run --source=$(NAME) -p


#######################################################################


all: build/src/libmiximus.so truffle-compile

clean: coverage-clean
	rm -rf build
	find . -name '__pycache__' -exec rm -rf '{}' ';'


#######################################################################


build:
	mkdir -p build

build/src/miximus_genKeys: build/Makefile
	make -C build

build/src/libmiximus.so: build/Makefile
	make -C build

build/Makefile: build CMakeLists.txt
	cd build && cmake ..

depends/libsnarks/CMakeLists.txt:
	git submodule update --init --recursive


#######################################################################


.PHONY: test
test: cxx-tests truffle-test python-test

python-test:
	$(COVERAGE) -m unittest discover test/

cxx-tests:
	./build/src/test_sha256_full_gadget
	./build/src/test_field_packing > /dev/null
	time ./build/src/hashpreimage_cli genkeys zksnark_element/hpi.pk.raw zksnark_element/hpi.vk.json
	ls -lah zksnark_element/hpi.pk.raw
	time ./build/src/hashpreimage_cli prove zksnark_element/hpi.pk.raw 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 zksnark_element/hpi.proof.json
	time ./build/src/hashpreimage_cli verify zksnark_element/hpi.vk.json zksnark_element/hpi.proof.json
	time ./build/src/test_load_proofkey zksnark_element/hpi.pk.raw

#######################################################################


coverage: coverage-combine coverage-report

coverage-clean:
	rm -rf .coverage .coverage.* htmlcov

coverage-combine:
	$(PYTHON) -m coverage combine

coverage-report:
	$(PYTHON) -m coverage report

coverage-html:
	$(PYTHON) -m coverage html


#######################################################################


python-dependencies: requirements requirements-dev

requirements:
	$(PYTHON) -m pip install -r requirements.txt

requirements-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

fedora-dependencies:
	dnf install procps-ng-devel gmp-devel boost-devel cmake g++

ubuntu-dependencies:
	apt-get install cmake make g++ libgmp-dev libboost-all-dev libprocps-dev

zksnark_element/pk.json: ./build/src/miximus_genKeys
	$< 3 zksnark_element/pk.json zksnark_element/vk.json


#######################################################################


nvm-install:
	./utils/nvm-install
	nvm install --lts

node_modules:
	$(NPM) install

$(TRUFFLE): node_modules

$(GANACHE): node_modules

.PHONY: truffle-test
truffle-test: $(TRUFFLE)
	$(NPM) run test

truffle-compile: $(TRUFFLE)
	$(TRUFFLE) compile

testrpc: $(TRUFFLE)
	$(NPM) run testrpc


#######################################################################


python-pyflakes:
	$(PYTHON) -mpyflakes $(NAME)

python-pylint:
	$(PYTHON) -mpylint $(NAME)
