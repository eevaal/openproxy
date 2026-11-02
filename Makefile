.PHONY: check format build

check:
	uv lock --check
	uv run --locked ruff check .
	uv run --locked ruff format --check src tests
	uv run --locked mypy
	uv run --locked pytest
	uv run --locked openproxy config validate --config examples/mock.yaml

format:
	uv run --locked ruff format src tests

build:
	uv build
