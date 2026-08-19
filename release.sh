#!/usr/bin/env bash
# release.sh — cut a coordinated OpenSCM CE + SaaS release.
#
# A release touches ~53 version references across 9 files in two repos.
# Doing that by hand is how 0.3.2–0.3.4 shipped CE v0.5.1 without
# auto-groups: CE_TAG in the SaaS workflow went stale and nothing caught
# it, because the path-dependency has no version constraint. This script
# makes every one of those edits together or not at all.
#
# Usage:
#   ./release.sh 0.7.12                 # CE + SaaS both to 0.7.12
#   ./release.sh 0.7.12 --dry-run       # show what would change
#   ./release.sh 0.7.12 --no-test       # skip the suite (not recommended)
#
# CE and SaaS carry the SAME version. Every SaaS release exists to pick up a
# CE release, so a separate SaaS number was translation overhead — and a third
# number to keep aligned with CE_TAG, which is how 0.3.2-0.3.4 shipped stale
# CE code. The SaaS version now IS the CE version it contains.
#
# Does NOT push. It prints the push commands — pushing is left to a human
# because the tags trigger the production release pipelines.

set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
info() { echo "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
ok()   { echo "    ${GREEN}✓${RESET} $*"; }
warn() { echo "    ${YELLOW}!${RESET} $*"; }
die()  { echo "${RED}Error:${RESET} $*" >&2; exit 1; }

# ── Arguments ────────────────────────────────────────────────────────────────
VERSION="${1:-}"; shift || true
DRY_RUN=0
RUN_TESTS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --no-test) RUN_TESTS=0; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ -n "$VERSION" ]] || die "Usage: $0 <version> [--dry-run] [--no-test]"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "Version must be X.Y.Z (got '$VERSION')"

CE_DIR="$(cd "$(dirname "$0")" && pwd)"
SAAS_DIR="${OPENSCM_SAAS_DIR:-$(cd "$CE_DIR/.." && pwd)/OpenSCM-SaaS}"
TODAY="$(date +%F)"

[[ -d "$SAAS_DIR/.git" ]] \
    || die "SaaS repo not found at $SAAS_DIR (set OPENSCM_SAAS_DIR to override)"

# Current versions, read before anything is modified.
CE_OLD="$(grep -m1 '^version = ' "$CE_DIR/scmserver/Cargo.toml" | cut -d'"' -f2)"
SAAS_OLD="$(grep -m1 '^version = ' "$SAAS_DIR/Cargo.toml" | cut -d'"' -f2)"

# SaaS carries the same version as CE — see the header.
SAAS_VERSION="$VERSION"

echo
info "Release plan"
echo "    CE     ${CE_OLD}  ->  ${VERSION}      (tag v${VERSION})"
echo "    SaaS   ${SAAS_OLD}  ->  ${SAAS_VERSION}      (tag v${SAAS_VERSION}, CE_TAG v${VERSION})"
echo "    Date   ${TODAY}"
echo "    SaaS repo: ${SAAS_DIR}"
echo

# ── Preflight ────────────────────────────────────────────────────────────────
info "Preflight"

for repo in "$CE_DIR" "$SAAS_DIR"; do
    name="$(basename "$repo")"
    [[ -z "$(git -C "$repo" status --porcelain)" ]] \
        || die "$name has uncommitted changes — commit or stash first"
    branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
    [[ "$branch" == "main" ]] \
        || warn "$name is on '$branch', not main"
done
ok "working trees clean"

git -C "$CE_DIR" rev-parse "v$VERSION" >/dev/null 2>&1 \
    && die "tag v$VERSION already exists in CE"
git -C "$SAAS_DIR" rev-parse "v$SAAS_VERSION" >/dev/null 2>&1 \
    && die "tag v$SAAS_VERSION already exists in SaaS"
ok "tags are free"

# An empty [Unreleased] means nobody wrote down what this release contains.
unreleased="$(awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f' "$CE_DIR/CHANGELOG.md" \
              | tr -d '[:space:]-')"
[[ -n "$unreleased" ]] \
    || die "CHANGELOG [Unreleased] is empty — document the release before cutting it"
ok "changelog has unreleased entries"

if [[ $RUN_TESTS -eq 1 ]]; then
    info "Running test suite"
    ( cd "$CE_DIR" && cargo test --workspace --locked ) >/dev/null \
        || die "tests failed — not releasing"
    ok "tests pass"
else
    warn "tests skipped (--no-test)"
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo
    info "Dry run — files that would change:"
    echo "    CE:   scmserver/Cargo.toml scmclient/Cargo.toml Cargo.lock CHANGELOG.md"
    echo "          docs/start/downloads.md docs/start/installation.md docs/guide/containers.md"
    echo "    SaaS: Cargo.toml Cargo.lock CHANGELOG.md .gitea/workflows/build_stable.yml"
    echo "    ($(grep -c "$CE_OLD" "$CE_DIR/docs/start/downloads.md" || echo 0) version refs in downloads.md alone)"
    exit 0
fi

# ── Edit: CE ─────────────────────────────────────────────────────────────────
info "Updating CE"

# One perl invocation per file: under -i, $. does not reset between files,
# so a line-number guard silently stops matching after the first one — which
# is exactly how the client version got left behind during testing.
for manifest in scmserver/Cargo.toml scmclient/Cargo.toml; do
    perl -pi -e "s/^version = \"\Q$CE_OLD\E\"/version = \"$VERSION\"/ if \$. < 10" \
        "$CE_DIR/$manifest"
    grep -q "^version = \"$VERSION\"" "$CE_DIR/$manifest" \
        || die "failed to bump version in $manifest"
    ok "$manifest"
done

# Promote [Unreleased] -> [X.Y.Z], leaving a fresh empty [Unreleased] on top.
perl -0pi -e "s/^## \[Unreleased\]\n/## [Unreleased]\n\n---\n\n## [$VERSION] - $TODAY\n/m" \
    "$CE_DIR/CHANGELOG.md"
grep -q "^## \[$VERSION\] - $TODAY" "$CE_DIR/CHANGELOG.md" \
    || die "failed to promote CHANGELOG to [$VERSION]"
ok "CHANGELOG promoted to [$VERSION]"

# Docs carry the version in download links and install commands. Only these
# three files are touched — feature notes elsewhere ("added in 0.7.5") refer
# to older versions and must not move.
for f in docs/start/downloads.md docs/start/installation.md docs/guide/containers.md; do
    [[ -f "$CE_DIR/$f" ]] || continue
    n="$(grep -c "$CE_OLD" "$CE_DIR/$f" || true)"
    perl -pi -e "s/\Q$CE_OLD\E/$VERSION/g" "$CE_DIR/$f"
    ok "$f ($n refs)"
done

( cd "$CE_DIR" && cargo build --workspace >/dev/null 2>&1 ) || die "CE build failed after bump"
ok "Cargo.lock refreshed"

# ── Edit: SaaS ───────────────────────────────────────────────────────────────
info "Updating SaaS"

perl -pi -e "s/^version = \"\Q$SAAS_OLD\E\"/version = \"$SAAS_VERSION\"/ if \$. < 10" \
    "$SAAS_DIR/Cargo.toml"
grep -q "^version = \"$SAAS_VERSION\"" "$SAAS_DIR/Cargo.toml" \
    || die "failed to bump SaaS version"
ok "Cargo.toml"

# The one that has bitten before: the path-dependency has no version
# constraint, so whatever CE_TAG points at is what gets compiled in.
WF="$SAAS_DIR/.gitea/workflows/build_stable.yml"
perl -pi -e "s/^(\s*CE_TAG:\s*)v.*/\${1}v$VERSION/" "$WF"
grep -q "CE_TAG: v$VERSION" "$WF" || die "failed to update CE_TAG in $WF"
ok "CE_TAG -> v$VERSION"

perl -0pi -e "s/^## \[Unreleased\]\n/## [Unreleased]\n\n---\n\n## [$SAAS_VERSION] - $TODAY\n\n### Changed\n- **Picks up CE v$VERSION.** Same version by definition; \`CE_TAG\` follows. See the CE CHANGELOG for what this release contains.\n/m" \
    "$SAAS_DIR/CHANGELOG.md"
grep -q "^## \[$SAAS_VERSION\] - $TODAY" "$SAAS_DIR/CHANGELOG.md" \
    || die "failed to promote SaaS CHANGELOG to [$SAAS_VERSION]"
ok "CHANGELOG promoted to [$SAAS_VERSION]"

( cd "$SAAS_DIR" && cargo build >/dev/null 2>&1 ) || die "SaaS build failed after bump"
ok "Cargo.lock refreshed"

# ── Commit + tag ─────────────────────────────────────────────────────────────
info "Committing and tagging"

git -C "$CE_DIR" add -A
git -C "$CE_DIR" commit -q -m "chore(release): OpenSCM $VERSION"
git -C "$CE_DIR" tag -a "v$VERSION" -m "OpenSCM $VERSION"
ok "CE   $(git -C "$CE_DIR" rev-parse --short HEAD)  tag v$VERSION"

git -C "$SAAS_DIR" add -A
git -C "$SAAS_DIR" commit -q -m "chore: bump to $SAAS_VERSION, CE_TAG v$VERSION"
git -C "$SAAS_DIR" tag -a "v$SAAS_VERSION" -m "OpenSCM SaaS $SAAS_VERSION — CE $VERSION"
ok "SaaS $(git -C "$SAAS_DIR" rev-parse --short HEAD)  tag v$SAAS_VERSION"

# ── Done ─────────────────────────────────────────────────────────────────────
cat <<EOF

$(info "Review, then push")

    git -C "$CE_DIR" show --stat HEAD
    git -C "$SAAS_DIR" show --stat HEAD

  ${BOLD}Push CE first${RESET} — the SaaS build clones CE at v$VERSION and will fail
  if that release has not published its assets yet.

    cd "$CE_DIR"   && git push origin main && git push origin v$VERSION
    cd "$SAAS_DIR" && git push origin main && git push origin v$SAAS_VERSION

  To undo before pushing:
    git -C "$CE_DIR"   tag -d v$VERSION   && git -C "$CE_DIR"   reset --hard HEAD~1
    git -C "$SAAS_DIR" tag -d v$SAAS_VERSION && git -C "$SAAS_DIR" reset --hard HEAD~1

EOF
