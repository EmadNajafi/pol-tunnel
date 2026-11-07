#!/usr/bin/env bash
# pol — interactive installer & tunnel manager (Backhaul/BackPack-style menu).
#
#   curl -fsSL https://raw.githubusercontent.com/EmadNajafi/pol-tunnel/main/install.sh | sudo bash
#
# (Not `sudo bash <(curl ...)`: sudo closes the /dev/fd pipe, so bash reports
# "/dev/fd/63: No such file or directory".)
#
# Manages one or more tunnels, each as a systemd service pol-<name>.service with
# its config at /etc/pol/<name>.toml. Needs root (Linux).
set -euo pipefail

REPO="EmadNajafi/pol-tunnel"
BIN="/usr/local/bin/pol"
MGR="/usr/local/bin/poltunnel"
CFGDIR="/etc/pol"
VERSION_TAG="latest"
RAW_URL="https://raw.githubusercontent.com/$REPO/main/install.sh"

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
  local arch base url tmp sums want got
  arch="$(detect_arch)"
  if [ "$VERSION_TAG" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION_TAG"
  fi
  url="$base/pol-linux-$arch"
  say "downloading pol ($arch) ..."
  # temp file next to the target: same filesystem, and not on a noexec /tmp
  tmp="$(mktemp "$BIN.XXXXXX")"; sums="$(mktemp)"
  if ! curl -fsSL "$url" -o "$tmp"; then
    err "download failed from $url"
    rm -f "$tmp" "$sums"; return 1
  fi
  # verify against the release's SHA256SUMS (catches truncated/corrupted downloads)
  if curl -fsSL "$base/SHA256SUMS" -o "$sums" 2>/dev/null && [ -s "$sums" ]; then
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
  rm -f "$sums"
  chmod 0755 "$tmp"
  if ! "$tmp" -version >/dev/null 2>&1; then
    err "downloaded file is not a working pol binary — not installing"
    rm -f "$tmp"; return 1
  fi
  mv -f "$tmp" "$BIN"   # atomic replace, safe while a service runs the old one
  mkdir -p "$CFGDIR"
  ok "installed $("$BIN" -version) at $BIN"
  # install this manager as the `poltunnel` command (atomic replace so it is
  # safe even when the running menu is itself /usr/local/bin/poltunnel)
  if curl -fsSL "$RAW_URL" -o "$MGR.new" 2>/dev/null && [ -s "$MGR.new" ]; then
    chmod 0755 "$MGR.new"; mv -f "$MGR.new" "$MGR"
    ok "menu command installed — just run:  poltunnel"
  else
    rm -f "$MGR.new"
    warn "could not install the 'poltunnel' command (no internet?); the menu still works via the one-liner"
  fi
}

ensure_installed() { [ -x "$BIN" ] || { warn "pol is not installed yet"; do_install; }; }

# ---------- transport picker (prints the chosen transport on stdout) ----------
pick_transport() {
  {
  say "  1) tcpmux    (default, recommended)"
  say "  2) tcp"
  say "  3) wsmux     (through CDN)"
  say "  4) wssmux    (TLS, recommended for encryption)"
  say "  5) ws"
  say "  6) wss"
  say "  7) spoofmux  (UDP+ARQ, optional IP spoofing)"
  say "  8) spoof"
  read -rp "transport [1]: " c
  } >&2
  c=${c:-1}
  case "$c" in
    1) echo tcpmux;; 2) echo tcp;; 3) echo wsmux;; 4) echo wssmux;; 5) echo ws;; 6) echo wss;; 7) echo spoofmux;; 8) echo spoof;; *) echo tcpmux;;
  esac
}

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
  systemctl daemon-reload
  if ! systemctl enable --now "pol-$name.service" >/dev/null 2>&1; then
    err "service pol-$name failed to start — see: journalctl -u pol-$name -n 30"
    return 1
  fi
}

valid_name() { [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; }

# ask_yn "prompt" <default y|n> -> returns 0 (yes) / 1 (no)
ask_yn() {
  local p=$1 d=$2 a
  read -rp "$p " a
  a=${a:-$d}
  [[ "${a,,}" == y* ]]
}

# ---------- create tunnel ----------
do_create() {
  ensure_installed
  local name; read -rp "tunnel name (e.g. main): " name
  valid_name "$name" || { err "name: letters, digits, _ or - only"; return 1; }
  [ -f "$CFGDIR/$name.toml" ] && { warn "a tunnel named '$name' already exists"; return 1; }

  say ""
  say "kind of tunnel:"
  say "  1) reverse SERVER  — this is the Iran side (public ports, others connect here)"
  say "  2) reverse CLIENT  — this is the kharej side (dials out to the server)"
  say "  3) direct SERVER   — L3 encrypted tunnel, this side listens"
  say "  4) direct CLIENT   — L3 encrypted tunnel, this side dials out"
  local kind; read -rp "choice [1]: " kind; kind=${kind:-1}

  local f="$CFGDIR/$name.toml" token
  case "$kind" in
    1) # reverse server
      local tr bind enc
      tr=$(pick_transport)
      read -rp "tunnel bind port [3080]: " bind; bind=${bind:-3080}
      enc=$(ask_yn "encrypt the tunnel (AES-256-GCM)? [Y/n]:" y && echo true || echo false)
      token="$(gen_token)"
      say "generated token (put the SAME token on the client):"
      say "  ${C_CYN}$token${C_RESET}"
      say ""
      say "port mappings — one per line, e.g.  443   or   8080=80   or   2000-2010"
      say "(empty line to finish)"
      local ports=() line
      while true; do read -rp "  port> " line; [ -z "$line" ] && break; ports+=("$line"); done
      [ ${#ports[@]} -eq 0 ] && ports=("443")
      {
        echo "[server]"
        echo "bind_addr = \"0.0.0.0:$bind\""
        echo "transport = \"$tr\""
        echo "token = \"$token\""
        echo "encryption = $enc"
        echo "heartbeat = 20"
        echo "web_port = 2060"
        echo "log_level = \"info\""
        printf 'ports = ['
        local first=1 p
        for p in "${ports[@]}"; do [ $first -eq 1 ] && first=0 || printf ', '; printf '"%s"' "$p"; done
        echo "]"
      } > "$f"
      ;;
    2) # reverse client
      local tr remote pool enc proxy
      tr=$(pick_transport)
      read -rp "server address (IRAN_IP:PORT): " remote
      read -rp "token (from the server): " token
      read -rp "connection_pool [8]: " pool; pool=${pool:-8}
      enc=$(ask_yn "encrypt the tunnel (must match the server)? [Y/n]:" y && echo true || echo false)
      proxy=$(ask_yn "send PROXY protocol v2 to the backend (real client IP)? [y/N]:" n && echo true || echo false)
      say "backup server addresses (optional, one per line, empty to finish):"
      local backups=() bl
      while true; do read -rp "  backup> " bl; [ -z "$bl" ] && break; backups+=("$bl"); done
      {
        echo "[client]"
        echo "remote_addr = \"$remote\""
        if [ ${#backups[@]} -gt 0 ]; then
          printf 'remote_addrs = ['
          local first=1 b
          for b in "${backups[@]}"; do [ $first -eq 1 ] && first=0 || printf ', '; printf '"%s"' "$b"; done
          echo "]"
        fi
        echo "transport = \"$tr\""
        echo "token = \"$token\""
        echo "encryption = $enc"
        echo "proxy_protocol = $proxy"
        echo "connection_pool = $pool"
        echo "heartbeat = 20"
        echo "web_port = 2061"
        echo "log_level = \"info\""
      } > "$f"
      ;;
    3|4) # direct
      local role=server; [ "$kind" = 4 ] && role=client
      read -rp "this side's tunnel IP [10.200.0.1]: " lip; lip=${lip:-10.200.0.1}
      read -rp "peer's tunnel IP [10.200.0.2]: " pip; pip=${pip:-10.200.0.2}
      if [ "$role" = server ]; then
        read -rp "UDP bind port [3090]: " dbind; dbind=${dbind:-3090}
        token="$(gen_token)"
        say "generated token (put the SAME token on the client):"
        say "  ${C_CYN}$token${C_RESET}"
        {
          echo "[direct]"; echo "role = \"server\""
          echo "bind_addr = \"0.0.0.0:$dbind\""
          echo "token = \"$token\""; echo "tun_name = \"pol-$name\""
          echo "local_ip = \"$lip\""; echo "peer_ip = \"$pip\""; echo "mtu = 1400"
          echo "log_level = \"info\""
        } > "$f"
      else
        read -rp "server address (IP:PORT): " dremote
        read -rp "token (from the server): " token
        {
          echo "[direct]"; echo "role = \"client\""
          echo "remote_addr = \"$dremote\""
          echo "token = \"$token\""; echo "tun_name = \"pol-$name\""
          echo "local_ip = \"$lip\""; echo "peer_ip = \"$pip\""; echo "mtu = 1400"
          echo "log_level = \"info\""
        } > "$f"
      fi
      ;;
    *) err "invalid choice"; return 1;;
  esac

  chmod 600 "$f"
  write_service "$name" || return 1
  ok "tunnel '$name' created and started"
  sleep 1
  systemctl --no-pager -l status "pol-$name.service" | sed -n '1,6p' || true
}

# ---------- list / status ----------
list_names() { ls "$CFGDIR"/*.toml 2>/dev/null | sed 's#.*/##; s#\.toml$##' || true; }

do_list() {
  local any=0 n st
  for n in $(list_names); do
    any=1
    st="$(systemctl is-active "pol-$n.service" 2>/dev/null || true)"
    [ "$st" = active ] && st="${C_GRN}active${C_RESET}" || st="${C_RED}$st${C_RESET}"
    local tr; tr="$(grep -E '^transport|^role' "$CFGDIR/$n.toml" 2>/dev/null | head -1 | sed 's/.*= *//; s/"//g' || true)"
    printf '  %-16s %-10s %s\n' "$n" "$tr" "$st"
  done
  # (an `[ ... ] && warn` as the last line would return 1 when there ARE
  # tunnels, and under `set -e` that silently killed the whole menu)
  if [ $any -eq 0 ]; then warn "no tunnels yet (create one from the menu)"; fi
  return 0
}

# prints the chosen tunnel name on stdout (menu + prompt go to stderr)
pick_tunnel() {
  local names=($(list_names))
  [ ${#names[@]} -eq 0 ] && { warn "no tunnels"; return 1; }
  local i=1 nm c
  { for nm in "${names[@]}"; do say "  $i) $nm"; i=$((i+1)); done
    read -rp "pick [1]: " c; } >&2
  c=${c:-1}
  [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 1 ] || { err "invalid choice"; return 1; }
  local sel="${names[$((c-1))]:-}"
  [ -n "$sel" ] || return 1
  printf '%s' "$sel"
}

do_startstop() {
  local n; n=$(pick_tunnel) || return
  say "  1) start   2) stop   3) restart"
  local a; read -rp "action [3]: " a; a=${a:-3}
  case "$a" in 1) systemctl start "pol-$n";; 2) systemctl stop "pol-$n";; *) systemctl restart "pol-$n";; esac
  ok "done"; systemctl --no-pager status "pol-$n" | sed -n '1,4p'
}

do_logs() { local n; n=$(pick_tunnel) || return; journalctl -u "pol-$n" --no-pager -n 30 -o cat; }

do_delete() {
  local n; n=$(pick_tunnel) || return
  systemctl disable --now "pol-$n.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/pol-$n.service" "$CFGDIR/$n.toml"
  systemctl daemon-reload
  ok "tunnel '$n' deleted"
}

# tunnel test between two servers
do_conntest() {
  ensure_installed
  say "${C_B}Connection Test${C_RESET} — runs every tunnel between this server and another for real"
  say "and shows which carry traffic steadily, which drop, and which never come up,"
  say "with round trip and speed. Nothing is installed; the test tunnels are gone when it ends."
  say ""
  say "  This server is:"
  say "    1) Iran    — start here, get the link"
  say "    2) Kharej  — paste the Iran server's link"
  local c; read -rp "choice [1]: " c; c=${c:-1}
  case "$c" in
    1) local host def; def="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
       read -rp "this server's public IP (the kharej dials it) [${def:-auto}]: " host; host=${host:-$def}
       [ "$(id -u)" -eq 0 ] || warn "not root — the direct tunnel and IP-spoofing check are left out"
       "$BIN" -conntest ${host:+-conntest-host "$host"} ;;
    2) local link; read -rp "test link: " link
       [ -z "$link" ] && { err "no link"; return 1; }
       "$BIN" -conntest-join "$link" ;;
  esac
}

do_linktest() {
  ensure_installed
  say "${C_B}Link Test${C_RESET} — latency / jitter / loss over TCP and UDP, forged-source check, and a recommendation"
  say "    1) listener — on the tunnel-host server (Iran)"
  say "    2) run      — on the other server (kharej)"
  local c; read -rp "choice [2]: " c; c=${c:-2}
  case "$c" in
    1) local p; read -rp "listen port [7000]: " p; p=${p:-7000}
       say "listening on :$p — run option 2 on the other server, then Ctrl-C"
       "$BIN" -probe-listen ":$p" ;;
    2) local peer; read -rp "listener address (OTHER_SERVER_IP:7000): " peer
       [ -z "$peer" ] && { err "no address"; return 1; }
       "$BIN" -probe "$peer" ;;
  esac
}

do_uninstall() {
  read -rp "remove pol, all tunnels and configs? [y/N]: " c
  [ "${c,,}" = y ] || { say "cancelled"; return; }
  local n
  for n in $(list_names); do systemctl disable --now "pol-$n.service" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/pol-$n.service"; done
  systemctl daemon-reload
  rm -rf "$CFGDIR" "$BIN" "$MGR"
  ok "pol removed"
}

# Run one menu action; on failure say so and wait, then go back to the menu.
run_action() {
  local rc=0
  "$@" || rc=$?
  [ $rc -eq 0 ] || err "that step failed (exit $rc) — nothing else was changed"
  pause || true
}

menu() {
  while true; do
    clear 2>/dev/null || true
    printf '%s%s pol tunnel manager %s %s\n' "$C_B" "$C_CYN" "$C_RESET" "$([ -x "$BIN" ] && "$BIN" -version 2>/dev/null || echo '(not installed)')"
    hr
    do_list || true
    hr
    say "  1) Install / update pol"
    say "  2) Create a tunnel"
    say "  3) Start / stop / restart a tunnel"
    say "  4) Show a tunnel's logs"
    say "  5) Delete a tunnel"
    say "  6) Connection Test — which tunnels work between two servers"
    say "  7) Link Test — latency / jitter / loss + a recommendation"
    say "  8) Uninstall everything"
    say "  0) Exit"
    [ -x "$MGR" ] && say "${C_DIM}  (reopen this menu any time with:  poltunnel)${C_RESET}"
    local c; read -rp $'\nchoice: ' c || { echo; exit 0; } # exit cleanly on EOF (non-interactive)
    # A failing action must report and return to the menu, not exit the script
    # (under `set -e` any non-zero return here used to close the menu silently).
    case "$c" in
      1) run_action do_install;;
      2) run_action do_create;;
      3) run_action do_startstop;;
      4) run_action do_logs;;
      5) run_action do_delete;;
      6) run_action do_conntest;;
      7) run_action do_linktest;;
      8) run_action do_uninstall;;
      0|q) exit 0;;
      *) ;;
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
  if [ ! -t 0 ]; then
    if { : </dev/tty; } 2>/dev/null; then
      exec </dev/tty
    else
      err "no terminal to show the menu on. Run it like this:"
      say "  curl -fsSL $RAW_URL | sudo bash"
      say "or after install just run:  sudo poltunnel"
      exit 1
    fi
  fi
  menu
}
main "$@"
