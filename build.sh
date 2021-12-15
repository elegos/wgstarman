#!/usr/bin/env sh

set -e

if [ -d ./dist ]; then
	rm -rf dist
fi
python3 setup.py sdist bdist_wheel
twine check dist/*
