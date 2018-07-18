PYTHON ?= python3
NAME ?= ethsnarks

COVERAGE = $(PYTHON) -mcoverage run --source=$(NAME) -p

#######################################################################

all: build/src/libmiximus.so

clean:
	rm -rf build .coverage .coverage.*
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
test:
	$(COVERAGE) -m unittest discover test/

coverage: coverage-combine coverage-report

coverage-combine:
	$(PYTHON) -m coverage combine

coverage-report:
	$(PYTHON) -m coverage report

coverage-html:
	$(PYTHON) -m coverage html

#######################################################################

requirements-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

fedora-dependencies:
	dnf install procps-ng-devel gmp-devel boost-devel

ubuntu-dependencies:
	apt-get install cmake make g++ libgmp-dev libboost-dev

zksnark_element/pk.json: ./build/src/miximus_genKeys
	$< 3 zksnark_element/pk.json zksnark_element/vk.json
