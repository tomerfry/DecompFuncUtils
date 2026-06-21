#!/usr/bin/env bash
#
# ghidra-claude.sh — route a Claude Code session to a specific Ghidra MCP server
# so multiple sessions can run in parallel against different binaries without
# colliding. Bash port of ghidra-claude.ps1.
#
# Each running Ghidra instance (with the DecompFuncUtils MCP server started)
# advertises itself in ~/.ghidra-mcp/server-<pid>.json. This launcher discovers
# the live servers, picks one (by loaded binary name, by port, or interactively),
# exports GHIDRA_MCP_URL for it, and execs `claude`. The project's .mcp.json reads
# ${GHIDRA_MCP_URL:-...}, so the chosen server is the only one this session sees.
#
# Usage:
#   ./tools/ghidra-claude.sh --binary libfoo.so [-- claude args...]
#   ./tools/ghidra-claude.sh --port 13101
#   ./tools/ghidra-claude.sh --list
#
# Liveness is decided by an HTTP probe of /discovery (portable across OSes —
# avoids unreliable cross-platform PID checks); unreachable servers' discovery
# files are pruned.

set -euo pipefail

PORT_DIR="${HOME}/.ghidra-mcp"

BINARY=""
PORT=""
DO_LIST=0
declare -a CLAUDE_ARGS=()

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---- arg parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary|-b) BINARY="${2:-}"; shift 2 ;;
        --port|-p)   PORT="${2:-}";   shift 2 ;;
        --list|-l)   DO_LIST=1;       shift ;;
        --help|-h)   usage 0 ;;
        --)          shift; CLAUDE_ARGS+=("$@"); break ;;
        *)           CLAUDE_ARGS+=("$1"); shift ;;
    esac
done

# ---- JSON parser detection (jq preferred, else python) ----
JSON_TOOL=""
if command -v jq >/dev/null 2>&1; then
    JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1; then
    JSON_TOOL="python3"
elif command -v python >/dev/null 2>&1; then
    JSON_TOOL="python"
else
    echo "error: need 'jq' or 'python' to parse discovery files." >&2
    exit 2
fi

# Emit a TAB-separated line: port \t pid \t project \t program \t programs(| joined)
parse_file() {
    local f="$1"
    if [[ "$JSON_TOOL" == "jq" ]]; then
        jq -r '[(.port|tostring), (.pid|tostring), (.project // ""), (.program // ""),
                ((.programs // []) | join("|"))] | @tsv' "$f" 2>/dev/null
    else
        "$JSON_TOOL" - "$f" <<'PYEOF' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
progs = d.get("programs") or []
fields = [str(d.get("port", "")), str(d.get("pid", "")),
          d.get("project") or "", d.get("program") or "", "|".join(progs)]
print("\t".join(fields))
PYEOF
    fi
}

# Probe /discovery; echo activeSessions on success, return non-zero on failure.
probe_sessions() {
    local port="$1" body
    body=$(curl -fsS --max-time 2 "http://127.0.0.1:${port}/discovery" 2>/dev/null) || return 1
    if [[ "$JSON_TOOL" == "jq" ]]; then
        echo "$body" | jq -r '.activeSessions // 0' 2>/dev/null || echo 0
    else
        echo "$body" | "$JSON_TOOL" -c \
            'import json,sys; print(json.load(sys.stdin).get("activeSessions",0))' 2>/dev/null || echo 0
    fi
}

if ! command -v curl >/dev/null 2>&1; then
    echo "error: 'curl' is required." >&2
    exit 2
fi

# ---- discovery: collect live servers into parallel arrays ----
declare -a S_PORT S_PID S_PROJ S_PROG S_PROGS S_SESS
discover() {
    [[ -d "$PORT_DIR" ]] || return 0
    local f line port pid proj prog progs sess
    for f in "$PORT_DIR"/server-*.json; do
        [[ -e "$f" ]] || continue
        line=$(parse_file "$f") || { continue; }
        [[ -n "$line" ]] || continue
        IFS=$'\t' read -r port pid proj prog progs <<<"$line"
        [[ -n "$port" ]] || continue
        if ! sess=$(probe_sessions "$port"); then
            # Server not answering — stale advertisement, remove it.
            rm -f "$f" 2>/dev/null || true
            continue
        fi
        S_PORT+=("$port"); S_PID+=("$pid"); S_PROJ+=("$proj")
        S_PROG+=("$prog"); S_PROGS+=("$progs"); S_SESS+=("$sess")
    done
}

fmt_programs() {
    # arg: index into the arrays
    local i="$1"
    if [[ -n "${S_PROGS[$i]}" ]]; then
        echo "${S_PROGS[$i]//|/, }"
    elif [[ -n "${S_PROG[$i]}" ]]; then
        echo "${S_PROG[$i]}"
    else
        echo "(no program loaded)"
    fi
}

discover
COUNT=${#S_PORT[@]}

# ---- --list ----
if [[ "$DO_LIST" -eq 1 ]]; then
    if [[ "$COUNT" -eq 0 ]]; then
        echo "No live Ghidra MCP servers found in ${PORT_DIR}/."
        echo "Start one in Ghidra: Tools -> MCP Server -> Start."
        exit 0
    fi
    echo
    echo "Live Ghidra MCP servers:"
    for ((i = 0; i < COUNT; i++)); do
        busy=""
        [[ "${S_SESS[$i]}" -gt 0 ]] 2>/dev/null && busy="  [in use: ${S_SESS[$i]} session(s)]"
        printf "  [%d] port %s  pid %s  project '%s'  programs: %s%s\n" \
            "$((i + 1))" "${S_PORT[$i]}" "${S_PID[$i]}" "${S_PROJ[$i]}" "$(fmt_programs "$i")" "$busy"
    done
    echo
    exit 0
fi

if [[ "$COUNT" -eq 0 ]]; then
    echo "error: no live Ghidra MCP servers found. In Ghidra: Tools -> MCP Server -> Start, then retry." >&2
    exit 1
fi

# ---- select a server -> CHOSEN (index) ----
CHOSEN=-1

if [[ -n "$PORT" ]]; then
    for ((i = 0; i < COUNT; i++)); do
        [[ "${S_PORT[$i]}" == "$PORT" ]] && CHOSEN=$i && break
    done
    [[ "$CHOSEN" -lt 0 ]] && { echo "error: no live MCP server on port $PORT." >&2; exit 1; }
elif [[ -n "$BINARY" ]]; then
    needle=$(echo "$BINARY" | tr '[:upper:]' '[:lower:]')
    declare -a HITS=()
    for ((i = 0; i < COUNT; i++)); do
        hay=$(echo "${S_PROG[$i]} ${S_PROGS[$i]}" | tr '[:upper:]' '[:lower:]')
        [[ "$hay" == *"$needle"* ]] && HITS+=("$i")
    done
    if [[ ${#HITS[@]} -eq 0 ]]; then
        echo "error: no live Ghidra instance has a binary matching '*${BINARY}*'. Use --list to see what's open." >&2
        exit 1
    fi
    if [[ ${#HITS[@]} -gt 1 ]]; then
        echo "error: multiple instances match '*${BINARY}*'. Narrow the name or use --port. (--list to see them.)" >&2
        exit 1
    fi
    CHOSEN=${HITS[0]}
elif [[ "$COUNT" -eq 1 ]]; then
    CHOSEN=0
else
    echo
    echo "Multiple Ghidra MCP servers are running. Choose one:"
    for ((i = 0; i < COUNT; i++)); do
        state="  [idle]"
        [[ "${S_SESS[$i]}" -gt 0 ]] 2>/dev/null && state="  [in use: ${S_SESS[$i]}]"
        printf "  [%d] port %s  '%s'  %s%s\n" \
            "$((i + 1))" "${S_PORT[$i]}" "${S_PROJ[$i]}" "$(fmt_programs "$i")" "$state"
    done
    read -r -p "Enter number: " sel
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [[ "$sel" -lt 1 ]] || [[ "$sel" -gt "$COUNT" ]]; then
        echo "error: invalid selection." >&2
        exit 1
    fi
    CHOSEN=$((sel - 1))
fi

if [[ "${S_SESS[$CHOSEN]}" -gt 0 ]] 2>/dev/null; then
    echo "warning: port ${S_PORT[$CHOSEN]} already has ${S_SESS[$CHOSEN]} active session(s); launching anyway will share that Ghidra instance." >&2
fi

export GHIDRA_MCP_URL="http://127.0.0.1:${S_PORT[$CHOSEN]}/sse"
echo "Routing this Claude session to Ghidra on port ${S_PORT[$CHOSEN]} (programs: $(fmt_programs "$CHOSEN"))"
echo "GHIDRA_MCP_URL = ${GHIDRA_MCP_URL}"

# Hand off to Claude Code in this same shell so it inherits GHIDRA_MCP_URL.
exec claude "${CLAUDE_ARGS[@]}"
