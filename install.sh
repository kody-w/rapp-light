#!/bin/sh
# install.sh — install a RAPP strain into the current user's home directory.
#
# NO ELEVATED PERMISSIONS. This script deliberately does not, and will not:
#   - use sudo, or ask for a password
#   - write outside $HOME
#   - register a system service, launch agent, or scheduled task
#   - modify the registry, /etc, or any shared configuration
#   - bind a privileged port
#
# Those constraints are the product requirement, not a side effect: this is
# built for users on managed enterprise workstations who cannot install
# software in the ordinary sense. Uninstalling is deleting one directory.
#
# POSIX sh on purpose — it runs on a locked-down box with no bash.

set -eu

RAPP_HOME="${RAPP_LIGHT_HOME:-$HOME/.rapp-light}"
REPO="${RAPP_LIGHT_REPO:-https://github.com/kody-w/rapp-light}"
BRANCH="${RAPP_LIGHT_BRANCH:-main}"

say() { printf '  %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

# Refuse to run as root. A strain installed by root into root's home is not the
# thing anyone wanted, and it is the shape that later needs elevated rights to
# uninstall.
if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    die "do not run this as root — a strain installs per-user, into \$HOME"
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required and was not found"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
case "$PYV" in
    3.[0-7]) die "python 3.8+ is required (found $PYV)" ;;
esac

say "RAPP Light — a strain of the RAPP brainstem"
say ""
say "  install to:   $RAPP_HOME"
say "  python:       $PYV  ($(command -v python3))"
say "  elevated:     no  (nothing outside \$HOME is touched)"
say ""

mkdir -p "$RAPP_HOME"

fetch() {
    # $1 = path in repo, $2 = destination
    url="$REPO/raw/$BRANCH/$1"
    if command -v curl >/dev/null 2>&1; then
        curl -sfL "$url" -o "$2" || die "could not fetch $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$url" || die "could not fetch $1"
    else
        die "neither curl nor wget is available"
    fi
}

# A truncated or corrupted download must not become a working-looking install.
# This verifies INTEGRITY, not authenticity: it proves the file arrived whole,
# not that it came from us. For an authenticated install, use the offline bundle
# from a signed release — see docs/DEPLOYMENT.md.
verify_py() {
    # $1 = file, $2 = a marker that must be present
    python3 - "$1" "$2" <<'PYEOF' || die "$1 arrived incomplete or corrupt — refusing to install"
import ast, sys
path, marker = sys.argv[1], sys.argv[2]
src = open(path, encoding="utf-8", errors="replace").read()
ast.parse(src)
assert marker in src, f"{path} is missing {marker!r}"
PYEOF
}

if [ -d "$RAPP_HOME/organs" ] && [ -f "$RAPP_HOME/tools/strainctl.py" ]; then
    say "existing installation found — updating the strain in place"
fi

mkdir -p "$RAPP_HOME/organs" "$RAPP_HOME/tools" "$RAPP_HOME/agents" \
         "$RAPP_HOME/withheld" "$RAPP_HOME/docs"

# An offline bundle: if the files are already beside this script, use them and
# make no network calls at all. Air-gapped installs need this path.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$HERE/organs/aa_strain_policy_agent.py" ]; then
    say "installing from the local bundle (no network access needed)"
    cp "$HERE/organs/"*.py       "$RAPP_HOME/organs/"
    cp "$HERE/tools/strainctl.py" "$RAPP_HOME/tools/"
    [ -d "$HERE/docs" ] && cp "$HERE/docs/"*.md "$RAPP_HOME/docs/" 2>/dev/null || true
else
    say "fetching the strain from $REPO"
    fetch organs/aa_strain_policy_agent.py "$RAPP_HOME/organs/aa_strain_policy_agent.py"
    fetch organs/strain_admin_agent.py     "$RAPP_HOME/organs/strain_admin_agent.py"
    fetch organs/strain_credential_agent.py "$RAPP_HOME/organs/strain_credential_agent.py"
    fetch tools/strainctl.py               "$RAPP_HOME/tools/strainctl.py"
    verify_py "$RAPP_HOME/organs/aa_strain_policy_agent.py"  "CAPABILITY_EVIDENCE"
    verify_py "$RAPP_HOME/organs/strain_admin_agent.py"      "RAPP_STRAIN_ADMIN_KEY"
    verify_py "$RAPP_HOME/organs/strain_credential_agent.py" "def adjudicate"
    verify_py "$RAPP_HOME/tools/strainctl.py"                "def cmd_approve"
    for d in THREAT-MODEL COMPLIANCE RAI RINGS CREDENTIALS DEPLOYMENT; do
        fetch "docs/$d.md" "$RAPP_HOME/docs/$d.md" || true
    done
fi

# The organs belong in agents/ — that is the load path the brainstem reads.
cp "$RAPP_HOME/organs/aa_strain_policy_agent.py" "$RAPP_HOME/agents/"
cp "$RAPP_HOME/organs/strain_admin_agent.py"     "$RAPP_HOME/agents/"
[ -f "$RAPP_HOME/organs/strain_credential_agent.py" ] && \
    cp "$RAPP_HOME/organs/strain_credential_agent.py" "$RAPP_HOME/agents/"

chmod 0700 "$RAPP_HOME" 2>/dev/null || true

# Close the auto-install oracle at the installer itself, not only at the policy
# layer. The brainstem shells `pip install <name>` for any module-level import
# it cannot satisfy; `basic_agent` was UNCLAIMED on PyPI on 2026-07-25 while 105
# registry agents imported it. See docs/THREAT-MODEL.md T11.
if [ -d "${BRAINSTEM_VENV:-$HOME/.brainstem/venv}" ]; then
    cat > "${BRAINSTEM_VENV:-$HOME/.brainstem/venv}/pip.conf" <<'PIPCONF'
[global]
no-index = true
disable-pip-version-check = true
require-virtualenv = true
PIPCONF
    say "closed the pip auto-install path in the brainstem venv"
    say "  (legitimate setup installs must pass --index-url explicitly)"
fi

# A launcher in ~/.local/bin — the one conventional per-user location, and the
# only thing written outside $RAPP_HOME. Still inside $HOME.
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
cat > "$BIN/strainctl" <<LAUNCH
#!/bin/sh
exec python3 "$RAPP_HOME/tools/strainctl.py" --manifest "$RAPP_HOME/strain.json" "\$@"
LAUNCH
chmod 0755 "$BIN/strainctl"

say ""
say "installed."
say ""
if [ ! -f "$RAPP_HOME/strain.json" ]; then
    say "No policy exists yet, so the strain currently admits NOTHING."
    say "That is the intended starting state. An administrator runs:"
    say ""
    say "    export RAPP_STRAIN_SEAL_KEY=...        # from your config management"
    say "    strainctl init \"Your Organisation\" --band ga"
    say "    strainctl scan $RAPP_HOME/agents"
    say "    strainctl approve <agent.py> --by you@example.com"
    say ""
else
    say "Existing policy kept. Current posture:"
    python3 "$RAPP_HOME/tools/strainctl.py" --manifest "$RAPP_HOME/strain.json" \
            report 2>/dev/null || true
fi
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) say "note: $BIN is not on your PATH; run strainctl as $BIN/strainctl" ;;
esac
say "docs for your security reviewer: $RAPP_HOME/docs/THREAT-MODEL.md"
