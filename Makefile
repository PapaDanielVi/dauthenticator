.DEFAULT_GOAL := help

DIST_DIR := dist
ZIP_NAME := dauthenticator.zip

.PHONY: help install icons typecheck test build package clean dev check-chrome

help:
	@echo "DAuthenticator build targets:"
	@echo "  make install      Install npm dependencies"
	@echo "  make icons        Generate extension PNG icons (16, 32, 48, 128)"
	@echo "  make typecheck    Run TypeScript compiler checks"
	@echo "  make test         Execute Vitest test suite"
	@echo "  make build        Run full production build into $(DIST_DIR)/"
	@echo "  make package      Produce $(ZIP_NAME) ready for Chrome Web Store / manual install"
	@echo "  make dev          Start Vite watch mode for development"
	@echo "  make clean        Remove build artifacts and packages"

install:
	npm install

icons:
	node scripts/generate-icons.mjs

typecheck:
	npm run typecheck

test:
	npm run test

build: typecheck icons
	npm run build:fast

package: clean build
	@echo "Packing extension archive..."
	cd $(DIST_DIR) && zip -q -r ../$(ZIP_NAME) .
	@echo "Created $(ZIP_NAME) successfully."

dev:
	npm run dev

clean:
	rm -rf $(DIST_DIR) $(ZIP_NAME)
