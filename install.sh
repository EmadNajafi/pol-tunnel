#!/usr/bin/env bash
# pol — interactive installer & tunnel manager.
#
#   curl -fsSL https://raw.githubusercontent.com/EmadNajafi/pol-tunnel/main/install.sh | sudo bash
#   curl -fsSL https://github.com/EmadNajafi/pol-tunnel/releases/latest/download/install.sh | sudo bash   # where raw.githubusercontent.com is blocked (Iran)
#
# Run that way it installs or updates pol and the `poltunnel` menu first, then
# opens the menu. `... | sudo bash -s -- update` updates without the menu.
#
# (Not `sudo bash <(curl ...)`: sudo closes the /dev/fd pipe, so bash reports
# "/dev/fd/63: No such file or directory".)
#
# Manages one or more tunnels, each as a systemd service pol-<name>.service with
# its config at /etc/pol/<name>.toml. Needs root (Linux).
set -euo pipefail
# Files this script creates hold tunnel tokens: private from the moment they
# exist (binaries and unit files get their modes set explicitly below).
umask 077

REPO="EmadNajafi/pol-tunnel"
BIN="/usr/local/bin/pol"
MGR="/usr/local/bin/poltunnel"
CFGDIR="/etc/pol"
VERSION_TAG="latest"
RAW_URL="https://raw.githubusercontent.com/$REPO/main/install.sh"
# The same script, attached to every release. It comes from github.com, which
# is reachable from networks that block raw.githubusercontent.com (Iran).
REL_URL="https://github.com/$REPO/releases/latest/download/install.sh"

# Downloads with timeouts, so a slow or blocked network fails with a message
# instead of hanging the installer (which looks like a freeze). The connect
# timeout covers the TLS handshake too, where a filtered host usually stalls.
curl_dl() { curl -fsSL --connect-timeout 15 --max-time 180 "$@"; }

# latest_tag prints the newest release tag (e.g. v0.3.2), read from the
# redirect of /releases/latest; empty when it cannot be told.
latest_tag() {
  curl -fsSI --connect-timeout 10 --max-time 20 -o /dev/null -w '%{redirect_url}' \
    "https://github.com/$REPO/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p'
}

C_RESET=$'\e[0m'; C_B=$'\e[1m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'; C_CYN=$'\e[36m'; C_DIM=$'\e[2m'

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_GRN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YEL" "$C_RESET" "$*"; }
err()  { printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
hr()   { printf '%s────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"; }

need_root() { [ "$(id -u)" -eq 0 ] || { err "run as root (sudo)"; exit 1; }; }

pause() { read -rp "$(printf '\n%spress Enter to continue%s ' "$C_DIM" "$C_RESET")" _; }

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) err "unsupported arch $(uname -m)"; exit 1 ;;
  esac
}

gen_token() {
  if [ -x "$BIN" ]; then "$BIN" -gen-token; else openssl rand -hex 32; fi
}

# ---------- install / update ----------
do_install() {
  local arch base url tmp sums want got tag cur skip=""
  arch="$(detect_arch)"
  if [ "$VERSION_TAG" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION_TAG"
  fi
  sums="$(mktemp)"
  # the release's SHA256SUMS (catches truncated/corrupted downloads)
  curl_dl "$base/SHA256SUMS" -o "$sums" 2>/dev/null || : > "$sums"

  # already the newest release? then only the menu is refreshed
  if [ "$VERSION_TAG" = latest ] && [ -x "$BIN" ]; then
    tag="$(latest_tag)"
    cur="$("$BIN" -version 2>/dev/null | awk '{print $2}')"
    if [ -n "$tag" ] && [ "v$cur" = "$tag" ]; then
      ok "pol is up to date ($tag)"
      skip=1
    fi
  fi

  if [ -z "$skip" ]; then
    url="$base/pol-linux-$arch"
    say "downloading pol ($arch) ..."
    # temp file next to the target: same filesystem, and not on a noexec /tmp
    tmp="$(mktemp "$BIN.XXXXXX")"
    if ! curl_dl "$url" -o "$tmp"; then
      err "download failed from $url (timed out or unreachable)"
      rm -f "$tmp" "$sums"; return 1
    fi
    if [ -s "$sums" ]; then
      want="$(awk -v f="pol-linux-$arch" '$2==f || $2=="*"f {print $1}' "$sums")"
      got="$(sha256sum "$tmp" | awk '{print $1}')"
      if [ -z "$want" ] || [ "$want" != "$got" ]; then
        err "checksum mismatch for pol-linux-$arch (expected ${want:-none}, got $got) — not installing"
        rm -f "$tmp" "$sums"; return 1
      fi
      ok "checksum verified"
    else
      warn "this release has no SHA256SUMS; skipping checksum verification"
    fi
    chmod 0755 "$tmp"
    if ! "$tmp" -version >/dev/null 2>&1; then
      err "downloaded file is not a working pol binary — not installing"
      rm -f "$tmp" "$sums"; return 1
    fi
    mv -f "$tmp" "$BIN"   # atomic replace, safe while a service runs the old one
    ok "installed $("$BIN" -version) at $BIN"
  fi
  mkdir -p "$CFGDIR"
  install_menu "$base" "$sums"
  rm -f "$sums"
  restart_stale_tunnels
}

# stale_tunnels prints the tunnels whose running process still executes a pol
# binary that has since been replaced (the kernel marks its exe "(deleted)").
# An update swaps the file but a running service keeps the old code until it
# is restarted.
stale_tunnels() {
  local n pid
  for n in $(list_names); do
    pid="$(systemctl show -p MainPID --value "pol-$n.service" 2>/dev/null || true)"
    [ -n "$pid" ] && [ "$pid" != 0 ] || continue
    case "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" in
      *"(deleted)") printf '%s\n' "$n" ;;
    esac
  done
}

# restart_stale_tunnels restarts tunnels still running an old binary. On a
# terminal it asks first (a restart drops the tunnel's connections for a
# moment); the non-interactive `update` just does it.
restart_stale_tunnels() {
  local stale n
  stale="$(stale_tunnels | tr '\n' ' ')"
  [ -n "${stale// /}" ] || return 0
  warn "still running the previous pol version: $stale"
  if [ -t 0 ] && ! ask_yn "restart them now to use $("$BIN" -version 2>/dev/null)? [Y/n]:" y; then
    warn "not restarted — they keep the old version until you restart them (menu option 3)"
    return 0
  fi
  for n in $stale; do
    if systemctl restart "pol-$n.service" >/dev/null 2>&1; then ok "restarted tunnel '$n'"; else warn "could not restart tunnel '$n'"; fi
  done
}

# next_web_port prints the first status-panel port from 2060 up that no
# existing tunnel config uses, so two tunnels on one server do not clash.
next_web_port() {
  local p=2060
  while grep -qsE "^web_port *= *$p\$" "$CFGDIR"/*.toml 2>/dev/null; do p=$((p + 1)); done
  printf '%s' "$p"
}

# install_menu installs this manager as the `poltunnel` command. It tries the
# copy attached to the release first (github.com, checked against
# SHA256SUMS), then raw.githubusercontent.com, which some networks (Iran)
# block — that download used to have no timeout and froze the update.
# The replace is atomic, so it is safe even when the running menu is
# /usr/local/bin/poltunnel itself.
install_menu() {
  local base=$1 sums=$2 src want got
  for src in "$base/install.sh" "$RAW_URL"; do
    rm -f "$MGR.new"
    curl_dl "$src" -o "$MGR.new" 2>/dev/null || continue
    # a real copy of this script, not an error page or a truncated download
    [ "$(head -c 19 "$MGR.new")" = "#!/usr/bin/env bash" ] && bash -n "$MGR.new" 2>/dev/null || continue
    if [ "$src" = "$base/install.sh" ] && [ -s "$sums" ]; then
      want="$(awk '$2=="install.sh" || $2=="*install.sh" {print $1}' "$sums")"
      got="$(sha256sum "$MGR.new" | awk '{print $1}')"
      [ -n "$want" ] && [ "$want" != "$got" ] && continue
    fi
    chmod 0755 "$MGR.new"; mv -f "$MGR.new" "$MGR"
    ok "menu command installed — just run:  poltunnel"
    return 0
  done
  rm -f "$MGR.new"
  warn "could not update the 'poltunnel' menu (download timed out or blocked); pol itself is fine"
}

ensure_installed() { [ -x "$BIN" ] || { warn "pol is not installed yet"; do_install; }; }


write_service() {
  local name=$1
  cat > "/etc/systemd/system/pol-$name.service" <<EOF
[Unit]
Description=pol tunnel ($name)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN -c $CFGDIR/$name.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "/etc/systemd/system/pol-$name.service"
  systemctl daemon-reload
  # forget a failed state left by an earlier tunnel of the same name
  systemctl reset-failed "pol-$name.service" >/dev/null 2>&1 || true
  if ! systemctl enable --now "pol-$name.service" >/dev/null 2>&1; then
    err "service pol-$name failed to start — see: journalctl -u pol-$name -n 30"
    return 1
  fi
  # `enable --now` succeeds even when pol exits right away (bad config, port
  # already in use): look again after a moment and show why
  sleep 1.5
  if [ "$(systemctl is-active "pol-$name.service" 2>/dev/null || true)" != active ]; then
    err "pol-$name started and stopped again:"
    journalctl -u "pol-$name.service" --no-pager -n 5 -o cat 2>/dev/null | sed 's/^/    /' >&2 || true
    return 1
  fi
}

# remove_tunnel deletes a tunnel's service, config and any leftovers, so the
# same name can be created again cleanly.
remove_tunnel() {
  local n=$1
  systemctl disable --now "pol-$n.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/pol-$n.service" "$CFGDIR/$n.toml"
  systemctl daemon-reload
  systemctl reset-failed "pol-$n.service" >/dev/null 2>&1 || true
  # a direct tunnel's interface, if its process was killed before it could remove it
  if ip link show "pol-$n" >/dev/null 2>&1; then ip link del "pol-$n" >/dev/null 2>&1 || true; fi
}

valid_name() { [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; }

# =====================================================================
#  Interface: screens, prompts that re-ask instead of aborting, wizards
# =====================================================================

# colours off when asked (NO_COLOR) or when the output is not a terminal
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
  C_RESET=""; C_B=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""; C_DIM=""
fi

ui_width() {
  local c; c="$(tput cols 2>/dev/null || echo 80)"
  [[ "$c" =~ ^[0-9]+$ ]] || c=80
  if [ "$c" -gt 78 ]; then c=78; fi
  if [ "$c" -lt 60 ]; then c=60; fi
  printf '%s' "$c"
}
rep() { local i out=""; for ((i = 0; i < $2; i++)); do out+="$1"; done; printf '%s' "$out"; }
hr() { printf '%s%s%s\n' "$C_DIM" "$(rep ─ "$(ui_width)")" "$C_RESET"; }
section() { printf '\n%s%s%s\n' "$C_B" "$1" "$C_RESET"; }
kv() { printf '  %s%-10s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"; }
hint() { printf '  %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
pause() { local _x; read -rp "$(printf '\n%spress Enter to continue%s ' "$C_DIM" "$C_RESET")" _x || true; }

banner() {
  local w inner left right pad
  w="$(ui_width)"; inner=$((w - 2))
  left="  pol tunnel manager"
  right="$([ -x "$BIN" ] && "$BIN" -version 2>/dev/null || echo 'not installed')  "
  pad=$((inner - ${#left} - ${#right})); if [ "$pad" -lt 1 ]; then pad=1; fi
  printf '%s╭%s╮%s\n' "$C_CYN" "$(rep ─ "$inner")" "$C_RESET"
  printf '%s│%s%s%s%s%*s%s%s%s│%s\n' "$C_CYN" "$C_RESET" "$C_B" "$left" "$C_RESET" "$pad" "" "$C_DIM" "$right" "$C_CYN" "$C_RESET"
  printf '%s╰%s╯%s\n' "$C_CYN" "$(rep ─ "$inner")" "$C_RESET"
}

# ask_yn "prompt" <default y|n> -> returns 0 (yes) / 1 (no)
ask_yn() {
  local p=$1 d=$2 a
  read -rp "$p " a || a=""
  a=${a:-$d}
  [[ "${a,,}" == y* ]]
}

# ask <var> <prompt> [default] [validator]  — asks again until the validator
# accepts the answer (it prints why not). Fails only when input ends.
ask() {
  local __var=$1 __prompt=$2 __def=${3:-} __val=${4:-} __ans
  while true; do
    if [ -n "$__def" ]; then
      read -rp "$(printf '  %s [%s%s%s]: ' "$__prompt" "$C_CYN" "$__def" "$C_RESET")" __ans || return 1
    else
      read -rp "  $__prompt: " __ans || return 1
    fi
    __ans="${__ans#"${__ans%%[![:space:]]*}"}"; __ans="${__ans%"${__ans##*[![:space:]]}"}"
    __ans=${__ans:-$__def}
    if [ -z "$__val" ] || "$__val" "$__ans"; then
      printf -v "$__var" '%s' "$__ans"
      return 0
    fi
  done
}

# choose <var> <default number> "key|label|description" ...  — a numbered list
# with a line of explanation each; asks again on anything that is not a number
# from the list.
choose() {
  local __var=$1 __def=$2; shift 2
  local __i=1 __o __k __l __d __ans
  for __o in "$@"; do
    IFS='|' read -r __k __l __d <<<"$__o"
    printf '   %s%2d)%s %-11s %s%s%s\n' "$C_CYN" "$__i" "$C_RESET" "$__l" "$C_DIM" "$__d" "$C_RESET"
    __i=$((__i + 1))
  done
  while true; do
    read -rp "$(printf '  choice [%s%s%s]: ' "$C_CYN" "$__def" "$C_RESET")" __ans || return 1
    __ans=${__ans:-$__def}
    if [[ "$__ans" =~ ^[0-9]+$ ]] && [ "$__ans" -ge 1 ] && [ "$__ans" -le $# ]; then
      __o="${!__ans}"
      printf -v "$__var" '%s' "${__o%%|*}"
      return 0
    fi
    err "choose a number from 1 to $#"
  done
}

# ---- validators (print the reason, return 1) ----
v_port() {
  if [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; then return 0; fi
  err "enter a port number from 1 to 65535"; return 1
}
v_free_port() {
  v_port "$1" || return 1
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; then
    err "port $1 is already in use on this server — pick another"; return 1
  fi
}
v_num() { if [[ "$1" =~ ^[0-9]+$ ]]; then return 0; fi; err "enter a number"; return 1; }
v_hostport() {
  if [[ "$1" =~ ^[^[:space:]:]+:[0-9]+$ || "$1" =~ ^\[[0-9a-fA-F:]+\]:[0-9]+$ ]]; then return 0; fi
  err "enter it as ADDRESS:PORT, for example 203.0.113.10:3080"; return 1
}
v_host() {
  if [[ "$1" =~ ^[A-Za-z0-9.:-]+$ ]]; then return 0; fi
  err "enter an IP address or a domain name"; return 1
}
v_ipv4() {
  if [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then return 0; fi
  err "enter an IPv4 address, for example 10.200.0.1"; return 1
}
v_token() {
  if [[ "$1" =~ ^[A-Za-z0-9._~+/=-]{8,}$ ]]; then return 0; fi
  err "paste the token from the server (at least 8 characters, no spaces or quotes)"; return 1
}
v_new_name() {
  if ! valid_name "$1"; then err "use letters, digits, _ or - only"; return 1; fi
  if [ -f "$CFGDIR/$1.toml" ]; then err "a tunnel named '$1' already exists — pick another name"; return 1; fi
}
v_new_direct_name() {
  v_new_name "$1" || return 1
  # the interface is named pol-<name>, and Linux allows 15 characters
  if [ ${#1} -gt 11 ]; then err "a direct tunnel's name can be at most 11 characters (it names the interface pol-$1)"; return 1; fi
}
v_portmap() {
  # (in a bracket expression "]" must come first to be literal)
  if [[ "$1" =~ ^[][0-9A-Za-z.:=-]+$ ]] && [[ "$1" =~ [0-9] ]]; then return 0; fi
  err "examples: 443   8080=80   2000-2010   443=10.0.0.5:8443"; return 1
}
v_paths() {
  if [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 16 ]; then return 0; fi
  err "paths must be a number from 1 to 16"; return 1
}

# ---- reading a tunnel's config and state ----
list_names() { ls "$CFGDIR"/*.toml 2>/dev/null | sed 's#.*/##; s#\.toml$##' || true; }

# cfg_get <file> <key> — the value of a top-level key, unquoted, without comments
cfg_get() {
  local line
  line="$(grep -m1 -E "^$2[[:space:]]*=" "$1" 2>/dev/null || true)"
  if [ -z "$line" ]; then return 0; fi
  line="${line#*=}"; line="${line#"${line%%[![:space:]]*}"}"
  case "$line" in
    \"*) line="${line#\"}"; printf '%s' "${line%%\"*}" ;;
    \[*) printf '%s' "${line%%]*}]" ;;
    *) printf '%s' "${line%%[[:space:]#]*}" ;;
  esac
}

tunnel_kind() {
  if grep -q '^\[server\]' "$1" 2>/dev/null; then printf 'reverse server'
  elif grep -q '^\[client\]' "$1" 2>/dev/null; then printf 'reverse client'
  elif grep -q '^\[direct\]' "$1" 2>/dev/null; then printf 'direct %s' "$(cfg_get "$1" role)"
  else printf 'unknown'; fi
}

# the tunnel's own status panel (127.0.0.1:web_port/stats), when it has one
tunnel_stats() {
  local wp; wp="$(cfg_get "$CFGDIR/$1.toml" web_port)"
  if [ -z "$wp" ] || [ "$wp" = 0 ]; then return 0; fi
  curl -s --max-time 1 "http://127.0.0.1:$wp/stats" 2>/dev/null || true
}
json_num() { printf '%s' "$1" | grep -oE "\"$2\":[0-9]+" | head -1 | sed 's/.*://' || true; }
json_bool() { printf '%s' "$1" | grep -oE "\"$2\":(true|false)" | head -1 | sed 's/.*://' || true; }

on_off() { if [ "$1" = true ]; then printf on; else printf off; fi; }
human_bytes() {
  awk -v n="${1:-0}" 'BEGIN { split("B KiB MiB GiB TiB", u, " "); i = 1; while (n >= 1024 && i < 5) { n /= 1024; i++ }
    if (i == 1) printf "%d %s", n, u[i]; else printf "%.1f %s", n, u[i] }'
}
fmt_dur() {
  local s=${1:-0}
  if [ "$s" -ge 86400 ]; then printf '%dd %dh' $((s / 86400)) $((s % 86400 / 3600))
  elif [ "$s" -ge 3600 ]; then printf '%dh %dm' $((s / 3600)) $((s % 3600 / 60))
  elif [ "$s" -ge 60 ]; then printf '%dm %ds' $((s / 60)) $((s % 60))
  else printf '%ds' "$s"; fi
}

# tunnel_state <name> — sets ST_COLOR / ST_TEXT (and ST_JSON for the caller):
# not only "the service runs" but whether the other server is actually connected.
tunnel_state() {
  local n=$1 f="$CFGDIR/$1.toml" act
  ST_JSON=""
  act="$(systemctl is-active "pol-$n.service" 2>/dev/null || true)"
  if [ "$act" != active ]; then
    ST_COLOR=$C_RED; ST_TEXT="○ ${act:-stopped}"
    return 0
  fi
  ST_COLOR=$C_GRN; ST_TEXT="● running"
  ST_JSON="$(tunnel_stats "$n")"
  if [ -z "$ST_JSON" ]; then return 0; fi
  case "$(tunnel_kind "$f")" in
    "reverse server")
      if [ "$(json_bool "$ST_JSON" client_connected)" = true ]; then
        ST_TEXT="● running · Kharej connected"
      else
        ST_COLOR=$C_YEL; ST_TEXT="● running · waiting for Kharej"
      fi ;;
    "reverse client")
      case "$(json_bool "$ST_JSON" server_connected)" in
        true) ST_TEXT="● running · connected to Iran" ;;
        false) ST_COLOR=$C_YEL; ST_TEXT="● running · cannot reach Iran" ;;
      esac ;;
  esac
  return 0
}

public_ip() { ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}' || true; }
is_private_ip() { [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]; }

# ---- "is there a newer release?" without ever blocking the menu ----
LATEST_CACHE="/run/pol-latest-tag"
refresh_latest() {
  if find "$LATEST_CACHE" -mmin -360 2>/dev/null | grep -q .; then return 0; fi
  (
    t="$(latest_tag || true)"
    if [ -n "$t" ]; then printf '%s' "$t" > "$LATEST_CACHE.tmp" && mv -f "$LATEST_CACHE.tmp" "$LATEST_CACHE"; fi
  ) >/dev/null 2>&1 &
}
update_note() {
  local tag cur
  tag="$(cat "$LATEST_CACHE" 2>/dev/null || true)"
  cur="$([ -x "$BIN" ] && "$BIN" -version 2>/dev/null | awk '{print $2}' || true)"
  if [ -n "$tag" ] && [ -n "$cur" ] && [ "v$cur" != "$tag" ]; then
    printf '%s%s is available%s — press %su%s to update' "$C_YEL" "$tag" "$C_RESET" "$C_B" "$C_RESET"
  fi
}

# ---- join code: everything the other server needs, in one line to paste ----
# pol://j.<base64url of "v=1;k=r;a=HOST:PORT;tr=...;tk=TOKEN;...">. It holds the
# token, so it is as secret as the token.
JOIN_PREFIX="pol://j."
code_encode() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
code_decode() {
  local s; s="$(printf '%s' "$1" | tr '_-' '/+')"
  case $((${#s} % 4)) in 2) s="$s==" ;; 3) s="$s=" ;; esac
  printf '%s' "$s" | base64 -d 2>/dev/null || true
}
code_field() { printf '%s' "$1" | tr ';' '\n' | sed -n "s/^$2=//p" | head -1; }

# join_code <tunnel name> <public host> — prints the code for a server tunnel
join_code() {
  local f="$CFGDIR/$1.toml" host=$2 kind port body
  kind="$(tunnel_kind "$f")"
  port="$(cfg_get "$f" bind_addr)"; port="${port##*:}"
  case "$kind" in
    "reverse server")
      body="v=1;k=r;a=$host:$port;tr=$(cfg_get "$f" transport);tk=$(cfg_get "$f" token)"
      body+=";e=$(cfg_get "$f" encryption);pf=$(cfg_get "$f" performance)" ;;
    "direct server")
      body="v=1;k=d;a=$host:$port;tk=$(cfg_get "$f" token)"
      # the two tunnel addresses swap places on the other side
      body+=";l=$(cfg_get "$f" peer_ip);p=$(cfg_get "$f" local_ip);c=$(cfg_get "$f" carrier)"
      body+=";n=$(cfg_get "$f" paths);m=$(cfg_get "$f" auto_mtu);s=$(cfg_get "$f" sni_domain)" ;;
    *) return 1 ;;
  esac
  printf '%s%s' "$JOIN_PREFIX" "$(code_encode "$body")"
}

# show_join <name> — ask for this server's public address, print the code and
# what to do with it
show_join() {
  local n=$1 host def
  def="$(public_ip)"
  section "Join code for '$n'"
  hint "The Kharej server needs this server's public address, the port, the token and"
  hint "the settings. The code below carries all of it — paste it there, type nothing."
  if [ -n "$def" ] && is_private_ip "$def"; then
    warn "$def looks like a private address — enter the public IP or domain the Kharej server can reach"
    def=""
  fi
  ask host "this server's public IP or domain" "$def" v_host || return 1
  printf '\n  %s%s%s\n\n' "$C_CYN" "$(join_code "$n" "$host")" "$C_RESET"
  local type=Reverse
  case "$(tunnel_kind "$CFGDIR/$n.toml")" in direct*) type=Direct ;; esac
  say "  On the Kharej server:"
  say "    1. run the same installer (or ${C_B}poltunnel${C_RESET})"
  say "    2. press ${C_B}n${C_RESET} (new tunnel), then ${C_B}$type${C_RESET} -> ${C_B}Kharej${C_RESET} -> ${C_B}Join code${C_RESET}"
  say "    3. paste the code"
  hint "Keep the code private: it contains the tunnel's token."
}

# ---- creating tunnels ----
T_TRANSPORTS=(
  "tcpmux|tcpmux|TCP, many connections over a few — the usual choice"
  "tcp|tcp|plain TCP, one connection per user"
  "wsmux|wsmux|WebSocket + mux — works through a CDN"
  "wssmux|wssmux|WebSocket over TLS + mux — looks like HTTPS"
  "ws|ws|WebSocket, one connection per user"
  "wss|wss|WebSocket over TLS, one connection per user"
  "spoofmux|spoofmux|UDP with its own reliability + mux — for lossy routes"
  "spoof|spoof|UDP with its own reliability, one connection per user"
)
T_PROFILES=(
  "balance|balance|light on CPU and RAM — small or shared server"
  "turbo|turbo|larger windows, quicker recovery — recommended"
  "aggressive|aggressive|pushes hardest, also through loss — more RAM and CPU"
  "throughput|throughput|bulk transfer (downloads/uploads) — not for games"
)

step() { printf '\n%s%s%s %s\n' "$C_B" "$1" "$C_RESET" "${2:-}"; }

# finish_create <name> — start the service; on failure leave nothing behind
finish_create() {
  local name=$1 f="$CFGDIR/$1.toml"
  chmod 600 "$f"
  if ! write_service "$name"; then
    remove_tunnel "$name"
    err "tunnel '$name' was not created (nothing was left behind) — fix the cause above and create it again"
    return 1
  fi
  ok "tunnel '$name' is running"
}

# confirm_create — the summary is on screen; last chance to back out
confirm_create() {
  if ask_yn "$(printf '\n  create this tunnel? [%sY%s/n]:' "$C_CYN" "$C_RESET")" y; then return 0; fi
  warn "cancelled — nothing was created"
  return 1
}

create_reverse_server() {
  local name tr bind enc perf token line f ports=() first p
  step "Reverse tunnel, Iran server" "— users connect here; the Kharej server connects to this one"
  ask name "tunnel name" "$(default_name main)" v_new_name || return 1
  step "Transport" "— how the two servers talk; must be the same on both"
  choose tr 1 "${T_TRANSPORTS[@]}" || return 1
  ask bind "tunnel port (the Kharej server connects to it)" 3080 v_free_port || return 1
  step "Public ports" "— what users connect to on this server"
  hint "443          this server :443  ->  Kharej 127.0.0.1:443"
  hint "8080=80      this server :8080 ->  Kharej 127.0.0.1:80"
  hint "2000-2010    a range          |  443=10.0.0.5:8443  to another host"
  while true; do
    if [ ${#ports[@]} -eq 0 ]; then
      ask line "port" "" v_portmap || return 1
    else
      read -rp "  another port (Enter to finish): " line || line=""
      if [ -z "$line" ]; then break; fi
      v_portmap "$line" || continue
    fi
    ports+=("$line")
  done
  step "Performance" "— use the same profile on both servers"
  choose perf 2 "${T_PROFILES[@]}" || return 1
  if ask_yn "$(printf '\n  encrypt the tunnel (AES-256-GCM)? [%sY%s/n]:' "$C_CYN" "$C_RESET")" y; then enc=true; else enc=false; fi

  section "Summary"
  kv name "$name"; kv kind "reverse tunnel, Iran server"; kv transport "$tr"; kv port "$bind  (the Kharej server connects to it)"
  kv "public" "${ports[*]}"; kv profile "$perf"; kv encryption "$enc"
  confirm_create || return 1

  token="$(gen_token)"
  f="$CFGDIR/$name.toml"
  {
    echo "[server]"
    echo "bind_addr = \"0.0.0.0:$bind\""
    echo "transport = \"$tr\""
    echo "token = \"$token\""
    echo "encryption = $enc"
    echo "performance = \"$perf\""
    echo "heartbeat = 20"
    echo "web_port = $(next_web_port)"
    echo "log_level = \"info\""
    printf 'ports = ['
    first=1
    for p in "${ports[@]}"; do
      if [ $first -eq 1 ]; then first=0; else printf ', '; fi
      printf '"%s"' "$p"
    done
    echo "]"
  } > "$f"
  finish_create "$name" || return 1
  show_join "$name" || true
}

# write_client <name> <remote> <transport> <token> <enc> <perf> <proxy> [pool] [backups...]
write_client() {
  local name=$1 remote=$2 tr=$3 token=$4 enc=$5 perf=$6 proxy=$7 pool=${8:-}
  shift 7; if [ $# -gt 0 ]; then shift; fi
  local f="$CFGDIR/$name.toml" first=1 b
  {
    echo "[client]"
    echo "remote_addr = \"$remote\""
    if [ $# -gt 0 ]; then
      printf 'remote_addrs = ['
      for b in "$@"; do
        if [ $first -eq 1 ]; then first=0; else printf ', '; fi
        printf '"%s"' "$b"
      done
      echo "]"
    fi
    echo "transport = \"$tr\""
    echo "token = \"$token\""
    echo "encryption = $enc"
    echo "performance = \"$perf\""
    echo "proxy_protocol = $proxy"
    if [ -n "$pool" ]; then echo "connection_pool = $pool"; fi
    echo "heartbeat = 20"
    echo "web_port = $(next_web_port)"
    echo "log_level = \"info\""
  } > "$f"
}

create_reverse_client() {
  local name tr remote token enc perf proxy pool line backups=()
  step "Reverse tunnel, Kharej server" "— connects out to the Iran server"
  ask name "tunnel name" "$(default_name main)" v_new_name || return 1
  ask remote "Iran server address (IP:PORT)" "" v_hostport || return 1
  ask token "token (shown on the Iran server)" "" v_token || return 1
  step "Transport" "— must be the same as on the server"
  choose tr 1 "${T_TRANSPORTS[@]}" || return 1
  step "Performance" "— use the same profile as the server"
  choose perf 2 "${T_PROFILES[@]}" || return 1
  if ask_yn "$(printf '\n  encrypt the tunnel (must match the server)? [%sY%s/n]:' "$C_CYN" "$C_RESET")" y; then enc=true; else enc=false; fi
  if ask_yn "$(printf '  send the real visitor IP to the backend (PROXY protocol v2)? [y/%sN%s]:' "$C_CYN" "$C_RESET")" n; then proxy=true; else proxy=false; fi
  while true; do
    read -rp "  backup server address (Enter for none): " line || line=""
    if [ -z "$line" ]; then break; fi
    v_hostport "$line" || continue
    backups+=("$line")
  done

  section "Summary"
  kv name "$name"; kv kind "reverse tunnel, Kharej server"; kv server "$remote"; kv transport "$tr"
  kv profile "$perf"; kv encryption "$enc"; kv "PROXY v2" "$proxy"
  if [ ${#backups[@]} -gt 0 ]; then kv backups "${backups[*]}"; fi
  confirm_create || return 1
  write_client "$name" "$remote" "$tr" "$token" "$enc" "$perf" "$proxy" "" ${backups[@]+"${backups[@]}"}
  finish_create "$name"
}

# write_direct <name> <role> <addr> <token> <local> <peer> <carrier> <paths> <auto_mtu> [sni] [spoof_src] [spoof_peer]
write_direct() {
  local name=$1 role=$2 addr=$3 token=$4 lip=$5 pip=$6 car=$7 paths=$8 amtu=$9 sni=${10:-} spsrc=${11:-} sppeer=${12:-}
  {
    echo "[direct]"
    echo "role = \"$role\""
    if [ "$role" = server ]; then echo "bind_addr = \"0.0.0.0:$addr\""; else echo "remote_addr = \"$addr\""; fi
    echo "token = \"$token\""
    echo "tun_name = \"pol-$name\""
    echo "local_ip = \"$lip\""
    echo "peer_ip = \"$pip\""
    echo "mtu = 1400"
    echo "carrier = \"$car\""
    if [ -n "$spsrc" ]; then echo "spoof_source = \"$spsrc\""; fi
    if [ -n "$sppeer" ]; then echo "spoof_peer_ip = \"$sppeer\""; fi
    if [ -n "$sni" ]; then echo "sni_domain = \"$sni\""; fi
    echo "paths = $paths"
    echo "auto_mtu = $amtu"
    echo "log_level = \"info\""
  } > "$CFGDIR/$name.toml"
}

create_direct() {
  local role=$1 name lip pip car spsrc="" sppeer="" sni="" paths amtu addr token
  if [ "$role" = server ]; then
    step "Direct tunnel, Iran server" "— an encrypted L3 link; this side listens"
  else
    step "Direct tunnel, Kharej server" "— an encrypted L3 link; this side connects out"
  fi
  ask name "tunnel name" "$(default_name l3)" v_new_direct_name || return 1
  if [ "$role" = server ]; then
    ask lip "this side's tunnel IP" 10.200.0.1 v_ipv4 || return 1
    ask pip "the other side's tunnel IP" 10.200.0.2 v_ipv4 || return 1
  else
    ask lip "this side's tunnel IP" 10.200.0.2 v_ipv4 || return 1
    ask pip "the other side's tunnel IP" 10.200.0.1 v_ipv4 || return 1
  fi
  step "Carrier" "— how this side's packets look on the wire (all but udp need root)"
  choose car 1 \
    "udp|udp|plain UDP" \
    "spoof|spoof|UDP with a forged source IP (the datacenter must allow it)" \
    "pck|pck|hand-built TCP segments, no real connection" \
    "sni|sni|pck, preceded by a TLS ClientHello naming an allowed domain" \
    "icmp|icmp|ICMP echo — when only ping gets through" || return 1
  if [ "$car" = spoof ]; then ask spsrc "forged source IP" 10.10.10.10 v_ipv4 || return 1; fi
  if [ "$car" = sni ]; then ask sni "domain to name in the TLS ClientHello" www.cloudflare.com v_host || return 1; fi
  ask paths "paths (parallel sockets, same on both sides)" 1 v_paths || return 1
  if ask_yn "$(printf '  measure the route and set the MTU automatically? [%sY%s/n]:' "$C_CYN" "$C_RESET")" y; then amtu=true; else amtu=false; fi

  if [ "$role" = server ]; then
    ask addr "port to listen on" 3090 v_port || return 1
    read -rp "  the other side's REAL IP, only if it uses carrier spoof (Enter = no): " sppeer || sppeer=""
    if [ -n "$sppeer" ]; then v_ipv4 "$sppeer" || return 1; fi
  else
    ask addr "Iran server address (IP:PORT)" "" v_hostport || return 1
    ask token "token (shown on the Iran server)" "" v_token || return 1
  fi

  section "Summary"
  kv name "$name"; kv kind "direct tunnel, $(if [ "$role" = server ]; then printf Iran; else printf Kharej; fi) server"; kv "tunnel IPs" "$lip (this side)  <->  $pip"
  kv carrier "$car"; kv paths "$paths"; kv "auto MTU" "$amtu"
  if [ "$role" = server ]; then kv listens "port $addr"; else kv server "$addr"; fi
  confirm_create || return 1

  if [ "$role" = server ]; then
    token="$(gen_token)"
    case "$car" in
      pck | sni) warn "allow inbound TCP on ports $addr-$((addr + paths - 1)) in this server's firewall" ;;
      icmp) warn "allow inbound ICMP (echo) in this server's firewall" ;;
      *) if [ "$paths" -gt 1 ]; then warn "open UDP ports $addr-$((addr + paths - 1)) in this server's firewall"; fi ;;
    esac
  fi
  write_direct "$name" "$role" "$addr" "$token" "$lip" "$pip" "$car" "$paths" "$amtu" "$sni" "$spsrc" "$sppeer"
  finish_create "$name" || return 1
  if [ "$role" = server ]; then show_join "$name" || true; fi
}

# create_from_code — the other server's join code fills in everything
create_from_code() {
  local want=${1:-} code body kind name addr token
  step "Join code" "— paste the code the Iran server showed"
  while true; do
    read -rp "  code: " code || return 1
    code="${code//[[:space:]]/}"
    if [ -z "$code" ]; then warn "cancelled"; return 1; fi
    body=""
    if [ "${code#"$JOIN_PREFIX"}" != "$code" ]; then body="$(code_decode "${code#"$JOIN_PREFIX"}")"; fi
    if [ "$(code_field "$body" v)" = 1 ] && [ -n "$(code_field "$body" a)" ] && [ -n "$(code_field "$body" tk)" ]; then break; fi
    err "that is not a complete join code — it starts with $JOIN_PREFIX; copy all of it (Enter to cancel)"
  done
  kind="$(code_field "$body" k)"; addr="$(code_field "$body" a)"; token="$(code_field "$body" tk)"
  # the code decides the type; say so when it is not the one picked on the way here
  if [ "$want" = reverse ] && [ "$kind" = d ]; then warn "this code is for a direct tunnel — creating that"; fi
  if [ "$want" = direct ] && [ "$kind" = r ]; then warn "this code is for a reverse tunnel — creating that"; fi

  section "From the code"
  case "$kind" in
    r)
      local tr enc perf
      tr="$(code_field "$body" tr)"; enc="$(code_field "$body" e)"; perf="$(code_field "$body" pf)"
      if [ "$enc" != true ]; then enc=false; fi
      case "$perf" in balance | turbo | aggressive | throughput) ;; *) perf=balance ;; esac
      kv kind "reverse tunnel, Kharej server"; kv server "$addr"; kv transport "$tr"; kv profile "$perf"; kv encryption "$enc"
      echo
      ask name "tunnel name" "$(default_name main)" v_new_name || return 1
      confirm_create || return 1
      write_client "$name" "$addr" "$tr" "$token" "$enc" "$perf" false
      finish_create "$name" ;;
    d)
      local lip pip car paths amtu sni
      lip="$(code_field "$body" l)"; pip="$(code_field "$body" p)"; car="$(code_field "$body" c)"
      paths="$(code_field "$body" n)"; amtu="$(code_field "$body" m)"; sni="$(code_field "$body" s)"
      if [ "$amtu" != false ]; then amtu=true; fi
      kv kind "direct tunnel, Kharej server"; kv server "$addr"; kv "tunnel IPs" "$lip (this side)  <->  $pip"
      kv carrier "${car:-udp}"; kv paths "${paths:-1}"
      if [ "$car" = spoof ]; then
        warn "carrier spoof needs a forged source set by hand — using udp on this side"
        car=udp
      fi
      echo
      ask name "tunnel name" "$(default_name l3)" v_new_direct_name || return 1
      confirm_create || return 1
      write_direct "$name" client "$addr" "$token" "$lip" "$pip" "${car:-udp}" "${paths:-1}" "$amtu" "$sni"
      finish_create "$name" ;;
    *) err "this code is for a kind of tunnel this version does not know — update pol (u) and try again"; return 1 ;;
  esac
}

# default_name <base> — base, or base2, base3 ... when taken
default_name() {
  local base=$1 i=2 n=$1
  while [ -f "$CFGDIR/$n.toml" ]; do n="$base$i"; i=$((i + 1)); done
  printf '%s' "$n"
}

# page <title> [subtitle] — each step of the wizard gets a screen of its own
page() {
  clear 2>/dev/null || true
  banner
  printf '\n  %s%s%s' "$C_B" "$1" "$C_RESET"
  if [ -n "${2:-}" ]; then printf '   %s%s%s' "$C_DIM" "$2" "$C_RESET"; fi
  printf '\n\n'
}

# kind_label — how a tunnel is named on screen: by type and by which server it
# is on, the way people think of it (the config still says server / client)
kind_label() {
  case "$1" in
    "reverse server") printf 'reverse/Iran' ;;
    "reverse client") printf 'reverse/Kharej' ;;
    "direct server") printf 'direct/Iran' ;;
    "direct client") printf 'direct/Kharej' ;;
    *) printf '%s' "$1" ;;
  esac
}

# do_create: 1) reverse or direct   2) Iran or Kharej   3) the details.
# In both types the Iran server listens and the Kharej server connects to it,
# so the Kharej side never needs an open inbound port.
do_create() {
  ensure_installed
  local type side how=manual
  page "New tunnel" "step 1 — the type"
  choose type 1 \
    "reverse|Reverse|ports on the Iran server are forwarded to the Kharej server — the usual tunnel" \
    "direct|Direct|a private encrypted network link (L3) between the two servers" || return 1

  page "New $type tunnel" "step 2 — which server is this?"
  choose side 1 \
    "iran|Iran|users arrive here; it waits for the Kharej server — set this one up first" \
    "kharej|Kharej|connects out to the Iran server — set it up second" || return 1

  if [ "$side" = kharej ]; then
    page "New $type tunnel — Kharej" "step 3 — the details"
    choose how 1 \
      "code|Join code|paste the code the Iran server showed — nothing else to type" \
      "manual|By hand|enter the address, the token and the settings yourself" || return 1
  fi

  page "New $type tunnel — $([ "$side" = iran ] && printf Iran || printf Kharej)"
  case "$type/$side/$how" in
    */kharej/code) create_from_code "$type" ;;
    reverse/iran/*) create_reverse_server ;;
    reverse/kharej/*) create_reverse_client ;;
    direct/iran/*) create_direct server ;;
    direct/kharej/*) create_direct client ;;
  esac
}

# ---- one tunnel: its screen and actions ----
set_performance() {
  local n=$1 f="$CFGDIR/$1.toml" cur perf over
  if grep -q '^\[direct\]' "$f"; then
    warn "'$n' is a direct (L3) tunnel — performance profiles apply to reverse tunnels only"
    return 0
  fi
  cur="$(cfg_get "$f" performance)"
  section "Performance profile of '$n'"
  hint "current: ${cur:-balance (not set)} — use the same profile on both servers"
  choose perf 2 "${T_PROFILES[@]}" || return 1
  if grep -q '^performance *=' "$f"; then
    sed -i "s/^performance *=.*/performance = \"$perf\"/" "$f"
  else
    sed -i "0,/^transport *=/s//performance = \"$perf\"\n&/" "$f"
    if ! grep -q '^performance *=' "$f"; then echo "performance = \"$perf\"" >> "$f"; fi
  fi
  # keys written in the config win over the profile: say so instead of surprising
  over="$(grep -oE '^(connection_pool|mux_window|mux_framesize|nodelay|channel_size)' "$f" | tr '\n' ' ' || true)"
  if [ -n "$over" ]; then warn "these keys in the config override the profile: $over(delete a line to use the profile's value)"; fi
  systemctl restart "pol-$n.service"
  ok "'$n' now uses the '$perf' profile (restarted) — set the same on the other server"
}

edit_config() {
  local n=$1 f="$CFGDIR/$1.toml" ed tmp out
  ed="${EDITOR:-}"
  if [ -z "$ed" ]; then
    if command -v nano >/dev/null 2>&1; then ed=nano; elif command -v vi >/dev/null 2>&1; then ed=vi; fi
  fi
  if [ -z "$ed" ]; then err "no editor found (install nano, or set EDITOR)"; return 1; fi
  tmp="$(mktemp "$CFGDIR/.$n.XXXXXX")"
  cp "$f" "$tmp"
  while true; do
    "$ed" "$tmp" || true
    if cmp -s "$f" "$tmp"; then rm -f "$tmp"; say "no changes"; return 0; fi
    # never put a config in place that pol would refuse to start with
    if out="$("$BIN" -check -c "$tmp" 2>&1)"; then break; fi
    err "the edited config is not valid: ${out#config: }"
    if ! ask_yn "  edit it again? [Y/n] (n = discard the changes):" y; then rm -f "$tmp"; warn "changes discarded"; return 0; fi
  done
  chmod 600 "$tmp"; mv -f "$tmp" "$f"
  ok "config saved"
  if ask_yn "  restart '$n' now to apply it? [Y/n]:" y; then
    systemctl restart "pol-$n.service"
    ok "restarted"
  else
    warn "the running tunnel keeps the old settings until it is restarted"
  fi
}

live_logs() {
  hint "live log of '$1' — Ctrl+C to go back"
  trap ':' INT
  journalctl -u "pol-$1.service" -n 30 -f -o cat || true
  trap - INT
  echo
}

confirm_delete() {
  local n=$1 a
  warn "this stops and removes the tunnel '$n' and its config"
  read -rp "  type the tunnel's name to confirm: " a || a=""
  if [ "$a" = "$n" ]; then return 0; fi
  say "cancelled — nothing was removed"
  return 1
}

draw_tunnel() {
  local n=$1 f="$CFGDIR/$1.toml" kind tr up
  kind="$(tunnel_kind "$f")"
  tunnel_state "$n"
  clear 2>/dev/null || true
  banner
  printf '\n  %sTUNNEL%s  %s%s%s    %s%s%s\n\n' "$C_DIM" "$C_RESET" "$C_B" "$n" "$C_RESET" "$ST_COLOR" "$ST_TEXT" "$C_RESET"
  case "$kind" in
    "reverse server")
      kv kind "reverse tunnel, Iran server — users connect to this one"
      kv transport "$(cfg_get "$f" transport)   encryption $(on_off "$(cfg_get "$f" encryption)")   profile $(p="$(cfg_get "$f" performance)"; printf '%s' "${p:-balance}")"
      kv listens "$(cfg_get "$f" bind_addr)  (the Kharej server connects here)"
      kv public "$(cfg_get "$f" ports | tr -d '[]"' | sed 's/,/  /g')" ;;
    "reverse client")
      kv kind "reverse tunnel, Kharej server — connects out to the Iran server"
      kv transport "$(cfg_get "$f" transport)   encryption $(on_off "$(cfg_get "$f" encryption)")   profile $(p="$(cfg_get "$f" performance)"; printf '%s' "${p:-balance}")"
      kv server "$(cfg_get "$f" remote_addr)" ;;
    direct*)
      kv kind "direct tunnel, $(if [ "$kind" = "direct server" ]; then printf Iran; else printf Kharej; fi) server — encrypted L3 link"
      kv carrier "$(cfg_get "$f" carrier)   paths $(cfg_get "$f" paths)   auto MTU $(cfg_get "$f" auto_mtu)"
      kv "tunnel IP" "$(cfg_get "$f" local_ip)  <->  $(cfg_get "$f" peer_ip)   (interface pol-$n)"
      if [ "$kind" = "direct server" ]; then kv listens "$(cfg_get "$f" bind_addr)"; else kv server "$(cfg_get "$f" remote_addr)"; fi ;;
  esac
  if [ -n "$ST_JSON" ]; then
    up="$(json_num "$ST_JSON" uptime_sec)"
    kv uptime "$(fmt_dur "${up:-0}")"
    if [ -n "$(json_num "$ST_JSON" bytes_in)" ]; then
      kv traffic "in $(human_bytes "$(json_num "$ST_JSON" bytes_in)")   out $(human_bytes "$(json_num "$ST_JSON" bytes_out)")   open connections $(json_num "$ST_JSON" active)"
    fi
  fi
  if stale_tunnels | grep -qx "$n"; then
    kv note "${C_YEL}still running the previous pol version — restart it (r)${C_RESET}"
  fi
  kv config "$f"
  section "Recent log"
  journalctl -u "pol-$n.service" --no-pager -n 6 -o cat 2>/dev/null | cut -c1-"$(($(ui_width) - 4))" | sed 's/^/    /' || true
  echo
  hr
  local tw=stop
  if [ "$(systemctl is-active "pol-$n.service" 2>/dev/null || true)" != active ]; then tw=start; fi
  printf '  %sr%s restart   %ss%s %s   %sl%s live log   %sc%s show config   %se%s edit config\n' \
    "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$tw" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET"
  case "$kind" in
    "reverse server") printf '  %sp%s performance profile   %sj%s join code for the Kharej server   %sd%s delete\n' "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" ;;
    "reverse client") printf '  %sp%s performance profile   %sd%s delete\n' "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" ;;
    "direct server") printf '  %sj%s join code for the Kharej server   %sd%s delete\n' "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" ;;
    *) printf '  %sd%s delete\n' "$C_CYN" "$C_RESET" ;;
  esac
  printf '  %sEnter%s back to the list\n' "$C_CYN" "$C_RESET"
}

tunnel_screen() {
  local n=$1 a
  while true; do
    if [ ! -f "$CFGDIR/$n.toml" ]; then return 0; fi
    draw_tunnel "$n"
    read -rp $'\n> ' a || return 0
    case "${a,,}" in
      "" | b | q | 0) return 0 ;;
      r) if systemctl restart "pol-$n.service"; then ok "restarted"; else err "restart failed"; fi; sleep 1 ;;
      s)
        if [ "$(systemctl is-active "pol-$n.service" 2>/dev/null || true)" = active ]; then
          if systemctl stop "pol-$n.service"; then ok "stopped"; else err "stop failed"; fi
        else
          if systemctl start "pol-$n.service"; then ok "started"; else err "start failed"; fi
        fi
        sleep 1 ;;
      l) live_logs "$n" ;;
      c) section "$CFGDIR/$n.toml"; sed 's/^/    /' "$CFGDIR/$n.toml"; pause ;;
      e) run_action edit_config "$n" ;;
      p) run_action set_performance "$n" ;;
      j) case "$(tunnel_kind "$CFGDIR/$n.toml")" in
           *server) run_action show_join "$n" ;;
           *) warn "the join code is made on the server side"; sleep 1 ;;
         esac ;;
      d) if confirm_delete "$n"; then remove_tunnel "$n"; ok "tunnel '$n' deleted"; sleep 1; return 0; else sleep 1; fi ;;
      *) ;;
    esac
  done
}

# ---- tools ----
do_conntest() {
  ensure_installed
  local c
  section "Connection Test"
  hint "Runs every kind of tunnel between this server and another for real, and shows"
  hint "which carry traffic steadily, with round trip and speed. Nothing stays installed."
  echo
  choose c 1 \
    "iran|Iran|start here: this server makes the test link" \
    "kharej|Kharej|paste the link the Iran server printed" || return 1
  case "$c" in
    iran)
      local host def; def="$(public_ip)"
      ask host "this server's public IP (the other server dials it)" "$def" v_host || return 1
      "$BIN" -conntest -conntest-host "$host" ;;
    kharej)
      local link
      ask link "test link" "" || return 1
      if [ -z "$link" ]; then err "no link"; return 1; fi
      "$BIN" -conntest-join "$link" ;;
  esac
}

do_linktest() {
  ensure_installed
  local c
  section "Link Test"
  hint "Latency, jitter and loss over TCP and UDP, a forged-source check, and a recommendation."
  echo
  choose c 2 \
    "listen|Listener|on the tunnel-host server (Iran) — run this first" \
    "run|Run|on the other server (kharej) — measures and reports" || return 1
  case "$c" in
    listen)
      local p; ask p "listen port" 7000 v_free_port || return 1
      say "listening on :$p — run the test on the other server, then press Ctrl+C here"
      "$BIN" -probe-listen ":$p" ;;
    run)
      local peer; ask peer "listener address (OTHER_SERVER_IP:7000)" "" v_hostport || return 1
      "$BIN" -probe "$peer" ;;
  esac
}

do_uninstall() {
  local n a count
  count="$(list_names | grep -c . || true)"
  section "Uninstall"
  warn "this removes pol, the poltunnel command, and all $count tunnel(s) with their configs"
  read -rp "  type 'uninstall' to confirm: " a || a=""
  if [ "$a" != uninstall ]; then say "cancelled — nothing was removed"; return 0; fi
  for n in $(list_names); do remove_tunnel "$n"; done
  rm -rf "$CFGDIR" "$BIN" "$MGR" "$LATEST_CACHE"
  ok "pol removed"
  exit 0
}

# Run one menu action; on failure say so and wait, then go back to the menu.
run_action() {
  local rc=0
  "$@" || rc=$?
  if [ $rc -ne 0 ]; then err "that step did not finish (exit $rc) — nothing else was changed"; fi
  pause || true
}

# ---- the main screen ----
NAMES=()
draw_main() {
  local n i=0 f kind via prof os host ip note
  clear 2>/dev/null || true
  banner
  host="$(hostname 2>/dev/null || true)"; ip="$(public_ip)"
  os="$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release 2>/dev/null | head -1)"
  printf '  %sserver%s  %s  ·  %s  ·  %s %s\n' "$C_DIM" "$C_RESET" "${host:-?}" "${ip:-no route}" "${os:-Linux}" "$(uname -m)"
  note="$(update_note)"
  if [ -n "$note" ]; then printf '  %supdate%s  %s\n' "$C_DIM" "$C_RESET" "$note"; fi
  if [ -n "${NOTICE:-}" ]; then printf '  %s\n' "$NOTICE"; NOTICE=""; fi # e.g. the result of the automatic update

  section "TUNNELS"
  NAMES=()
  for n in $(list_names); do NAMES+=("$n"); done
  if [ ${#NAMES[@]} -eq 0 ]; then
    hint "none yet — press n to create the first one"
    hint "(set up the Iran server first, then the Kharej server with its join code)"
  else
    printf '  %s%-3s %-12s %-15s %-9s %-11s %s%s\n' "$C_DIM" "#" "NAME" "KIND" "VIA" "PROFILE" "STATE" "$C_RESET"
    for n in "${NAMES[@]}"; do
      i=$((i + 1)); f="$CFGDIR/$n.toml"
      kind="$(tunnel_kind "$f")"
      case "$kind" in
        direct*) via="$(cfg_get "$f" carrier)"; prof="-" ;;
        *) via="$(cfg_get "$f" transport)"; prof="$(cfg_get "$f" performance)" ;;
      esac
      tunnel_state "$n"
      printf '  %s%-3s%s %-12s %-15s %-9s %-11s %s%s%s\n' "$C_CYN" "$i" "$C_RESET" "${n:0:12}" "$(kind_label "$kind")" "${via:-?}" "${prof:-balance}" "$ST_COLOR" "$ST_TEXT" "$C_RESET"
    done
    if [ -n "$(stale_tunnels)" ]; then
      printf '  %s! some tunnels still run the previous pol version — open one and restart it%s\n' "$C_YEL" "$C_RESET"
    fi
  fi
  echo
  hr
  if [ ${#NAMES[@]} -gt 0 ]; then
    printf '  %s1-%d%s open a tunnel   %sn%s new tunnel   %st%s connection test   %sl%s link test\n' \
      "$C_CYN" "${#NAMES[@]}" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET"
  else
    printf '  %sn%s new tunnel   %st%s connection test   %sl%s link test\n' "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET"
  fi
  printf '  %su%s install / update   %sx%s uninstall   %sq%s quit' "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET" "$C_CYN" "$C_RESET"
  if [ -x "$MGR" ]; then printf '        %s(reopen any time: poltunnel)%s' "$C_DIM" "$C_RESET"; fi
  echo
}

menu() {
  local c
  refresh_latest || true
  while true; do
    draw_main
    read -rp $'\n> ' c || { echo; exit 0; } # exit cleanly on EOF (non-interactive)
    # A failing action must report and return to the menu, not exit the script
    # (under `set -e` any non-zero return here used to close the menu silently).
    case "${c,,}" in
      n) run_action do_create ;;
      t) run_action do_conntest ;;
      l) run_action do_linktest ;;
      u) run_action do_install; rm -f "$LATEST_CACHE"; refresh_latest || true ;;
      x) run_action do_uninstall ;;
      q | 0 | exit) exit 0 ;;
      *)
        if [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 1 ] && [ "$c" -le ${#NAMES[@]} ]; then
          tunnel_screen "${NAMES[$((c - 1))]}" || true
        fi ;;
    esac
  done
}

need_root
# The menu is interactive. When the script is piped in (`curl | sudo bash`),
# stdin is the pipe, so read the answers from the terminal instead; with no
# terminal at all, say how to run it rather than spin.
# Everything runs from one function called on the last line: bash has read the
# whole call before it runs, so reattaching stdin to the terminal below is safe
# even when the script itself arrived on stdin (`curl ... | sudo bash`).
main() {
  # Non-interactive commands, for piping onto a headless server without the
  # menu (which needs a terminal and otherwise looks frozen while it waits):
  #   curl -fsSL URL | sudo bash -s -- update     # install or update pol + the menu
  case "${1:-}" in
    install|update)
      if do_install; then exit 0; else exit 1; fi
      ;;
    "" ) ;; # no argument: fall through to the interactive menu
    * )
      err "unknown command: $1"
      say "use:  update   (install/update non-interactively), or no argument for the menu"
      exit 1
      ;;
  esac
  if [ ! -t 0 ]; then
    if { : </dev/tty; } 2>/dev/null; then
      exec </dev/tty
    else
      err "no terminal to show the menu on. To install or update without the menu, run:"
      say "  curl -fsSL $REL_URL | sudo bash -s -- update"
      say "or, with a terminal, for the menu:  sudo poltunnel"
      exit 1
    fi
  fi
  # Run through the one-liner (curl ... | sudo bash) rather than as the
  # installed `poltunnel`: install or update first — that is what the
  # one-liner is for — then show the menu. Up to date = only the menu is
  # refreshed, no binary download.
  case "$0" in
    "$MGR" | */poltunnel | poltunnel) ;;
    *)
      say "${C_B}checking for updates ...${C_RESET}"
      if do_install; then
        NOTICE="${C_GRN}✓${C_RESET} up to date: $("$BIN" -version 2>/dev/null)"
      else
        NOTICE="${C_YEL}!${C_RESET} automatic update failed (see above) — press u to retry"
        pause || true
      fi
      ;;
  esac
  menu
}
main "$@"
