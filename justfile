[private]
default:
    @just --list

install:
    uv lock --upgrade
    uv sync --all-extras --frozen
    @just hook

lint:
    uv run prek run --all-files

test *args:
    uv run --no-sync cargo test --profile release
    uv run --no-sync pytest {{ args }}

typecheck:
    uv run pyrefly check

publish:
    rm -rf dist
    uv build
    uv publish --token $PYPI_TOKEN

hook:
    uv run prek install --install-hooks --overwrite

unhook:
    uv run prek uninstall
