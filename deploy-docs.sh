#!/usr/bin/env bash
# deploy-docs.sh — build the openscm.io documentation site and publish it.
#
# The docs live in this repository (docs/ + mkdocs.yml), so the web server
# checks this repo out rather than a separate docs repo. The checkout is
# sparse: the repo carries ~120 MB of embedded static assets that the docs
# build has no use for, and a blobless sparse clone keeps the web server's
# copy to a few MB.
#
# Usage:  ./deploy-docs.sh            # pull, build, publish
#         ./deploy-docs.sh --build    # build only, don't touch the web root
#         ./deploy-docs.sh --strict   # fail on broken links / config warnings
#
# First-time setup on the web server:
#   git clone --filter=blob:none --sparse https://github.com/easysysio/OpenSCM
#   cd OpenSCM && git sparse-checkout set docs mkdocs.yml deploy-docs.sh

set -euo pipefail

WEB_ROOT="${WEB_ROOT:-/var/www/openscm}"
BUILD_ONLY=0
STRICT=""
for arg in "$@"; do
    case "$arg" in
        --build)  BUILD_ONLY=1 ;;
        --strict) STRICT="--strict" ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")"

echo "==> Updating sources"
git pull --ff-only

echo "==> Building site"
# --strict is opt-in rather than the default: it promotes MkDocs warnings to
# errors, which is what you want when checking your work, but it would also
# abort a routine deploy over something cosmetic (e.g. an unrecognised config
# key on an older MkDocs). Run `./deploy-docs.sh --build --strict` after
# editing docs to catch broken links before publishing.
mkdocs build $STRICT --site-dir site

if [[ $BUILD_ONLY -eq 1 ]]; then
    echo "==> Built to ./site (not published)"
    exit 0
fi

# Publish atomically-ish: stage the new site next to the live one and swap,
# so a failed copy can't leave the site half-replaced (the old `rm -rf` then
# `cp` left a window where openscm.io served nothing).
STAGING="${WEB_ROOT}.new"
PREVIOUS="${WEB_ROOT}.prev"

echo "==> Publishing to ${WEB_ROOT}"
rm -rf "$STAGING"
cp -r site "$STAGING"

if [[ -d "$WEB_ROOT" ]]; then
    rm -rf "$PREVIOUS"
    mv "$WEB_ROOT" "$PREVIOUS"
fi
mv "$STAGING" "$WEB_ROOT"

echo "==> Done — previous site kept at ${PREVIOUS}"
