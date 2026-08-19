#!/usr/bin/env bash
#
# hyvpn installer — Hysteria2 VPN with a Telegram control bot.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/siutstasy999/hyvpn-tg/main/install.sh)
#
# Ubuntu 22.04/24.04 and Debian 11/12. Re-running upgrades an existing install
# without touching its secrets, database or TLS certificate.
#
set -Eeuo pipefail

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

REPO="${HYVPN_REPO:-siutstasy999/hyvpn-tg}"
REF="${HYVPN_REF:-main}"

INSTALL_DIR=/opt/hyvpn
CONF_DIR=/etc/hyvpn
DATA_DIR=/var/lib/hyvpn
HYSTERIA_STATE_DIR=/var/lib/hysteria
ACME_DIR="$HYSTERIA_STATE_DIR/acme"
CERT_STATUS_PATH="$DATA_DIR/cert.json"
SERVICE_USER=hyvpn
HYSTERIA_USER=hysteria
WRAPPER=/usr/local/bin/hyvpn
UNITS=(hy-core.service hy-bot.service hysteria-server.service hy-certwatch.service hy-certwatch.timer)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /tmp)"
TMP_DIR=""
SOURCE_DIR=""

# answers
DOMAIN="${HYVPN_DOMAIN:-}"
EMAIL="${HYVPN_EMAIL:-}"
BOT_TOKEN="${HYVPN_BOT_TOKEN:-}"
ADMIN_IDS="${HYVPN_ADMIN_IDS:-}"
LOCATION="${HYVPN_LOCATION:-}"
# Left empty on purpose: a pre-set value makes ask()/choose() skip the
# question. The defaults live in ask_everything().
PORT="${HYVPN_PORT:-}"
LANG_CHOICE="${HYVPN_LANG:-}"
SETUP_UFW="${HYVPN_UFW:-yes}"
ASSUME_YES="${HYVPN_YES:-no}"
DRY_RUN="${HYVPN_DRY_RUN:-no}"
ACTION=install
FIRST_KEY_LABEL="${HYVPN_FIRST_KEY:-}"

# discovered state
EXISTING_INSTALL=no
KEEP_CERT=no
STATS_SECRET=""
BOT_USERNAME=""
PUBLIC_IP=""
QR_SUPPORT=yes

# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; BLUE=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

STEP_NO=0
step()  { STEP_NO=$((STEP_NO + 1)); printf '\n%s[%d/%d]%s %s%s%s\n' "$BLUE" "$STEP_NO" "$TOTAL_STEPS" "$RESET" "$BOLD" "$1" "$RESET"; }
info()  { printf '      %s\n' "$1"; }
ok()    { printf '      %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '      %s!%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
die()   { printf '\n%serror:%s %s\n' "$RED" "$RESET" "$1" >&2; exit 1; }

TOTAL_STEPS=11

banner() {
    printf '%s' "$BOLD"
    cat <<'ART'
  _
 | |__  _   _ _   ______  _ __
 | '_ \| | | | | / /  _ \| '_ \
 | | | | |_| | |/ /| |_) | | | |
 |_| |_|\__, |___/ | .__/|_| |_|
        |___/      |_|
ART
    printf '%s' "$RESET"
    printf ' %sHysteria2 VPN + Telegram bot%s\n' "$DIM" "$RESET"
}

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    # The EXIT trap's status becomes the script's status, so never fail here.
    return 0
}
trap cleanup EXIT

on_error() {
    local line=$1
    printf '\n%sInstallation failed%s (line %s).\n' "$RED" "$RESET" "$line" >&2
    printf 'Logs:\n  journalctl -u hy-core -u hy-bot -u hysteria-server -n 50 --no-pager\n' >&2
}

# --------------------------------------------------------------------------- #
# input helpers
# --------------------------------------------------------------------------- #

TTY=/dev/tty
interactive() { [[ "$ASSUME_YES" != "yes" ]] && [[ -r "$TTY" ]]; }

ask() {
    # ask VARNAME "question" "default" [validator]
    local __var=$1 question=$2 default=${3:-} validator=${4:-} answer current
    current="${!__var:-}"
    if [[ -n "$current" ]]; then
        if [[ -n "$validator" ]] && ! "$validator" "$current"; then
            die "invalid value for $__var: $current"
        fi
        return 0
    fi
    if ! interactive; then
        [[ -n "$default" ]] || die "missing required value: $__var (no tty for questions)"
        printf -v "$__var" '%s' "$default"
        return 0
    fi
    while true; do
        if [[ -n "$default" ]]; then
            printf '      %s %s[%s]%s: ' "$question" "$DIM" "$default" "$RESET" >"$TTY"
        else
            printf '      %s: ' "$question" >"$TTY"
        fi
        IFS= read -r answer <"$TTY" || answer=""
        answer="${answer:-$default}"
        [[ -z "$answer" ]] && continue
        if [[ -n "$validator" ]] && ! "$validator" "$answer"; then
            printf '      %s!%s не подходит, попробуйте ещё раз\n' "$YELLOW" "$RESET" >"$TTY"
            continue
        fi
        printf -v "$__var" '%s' "$answer"
        return 0
    done
}

confirm() {
    # confirm "question" [y|n]
    local question=$1 default=${2:-y} answer
    if ! interactive; then
        [[ "$default" == "y" ]]
        return
    fi
    local hint="[Y/n]"
    [[ "$default" == "y" ]] || hint="[y/N]"
    printf '      %s %s%s%s: ' "$question" "$DIM" "$hint" "$RESET" >"$TTY"
    IFS= read -r answer <"$TTY" || answer=""
    answer="${answer:-$default}"
    [[ "${answer,,}" == y* ]]
}

choose() {
    # choose VARNAME "question" "value1:label1" "value2:label2" ...
    local __var=$1 question=$2; shift 2
    local options=("$@") index answer
    if [[ -n "${!__var:-}" ]]; then return 0; fi
    if ! interactive; then
        printf -v "$__var" '%s' "${options[0]%%:*}"
        return 0
    fi
    printf '      %s\n' "$question" >"$TTY"
    index=1
    for option in "${options[@]}"; do
        printf '        %s) %s\n' "$index" "${option#*:}" >"$TTY"
        index=$((index + 1))
    done
    while true; do
        printf '      1-%d %s[1]%s: ' "${#options[@]}" "$DIM" "$RESET" >"$TTY"
        IFS= read -r answer <"$TTY" || answer=""
        answer="${answer:-1}"
        if [[ "$answer" =~ ^[0-9]+$ ]] && (( answer >= 1 && answer <= ${#options[@]} )); then
            printf -v "$__var" '%s' "${options[answer-1]%%:*}"
            return 0
        fi
    done
}

# validators
valid_domain() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; }
valid_email()  { [[ "$1" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; }
valid_token()  { [[ "$1" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{20,}$ ]]; }
# Spaces are tolerated here and stripped by the caller: "123, 456" is a
# natural thing to type.
valid_ids()    { [[ "${1//[[:space:]]/}" =~ ^[0-9]+(,[0-9]+)*$ ]]; }
valid_port()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

usage() {
    cat <<EOF
${BOLD}hyvpn installer${RESET}

Usage: install.sh [options]

Options:
  --domain DOMAIN        server domain (A/AAAA record must point here)
  --email EMAIL          e-mail for Let's Encrypt notifications
  --bot-token TOKEN      Telegram bot token from @BotFather
  --admin-id IDS         comma-separated Telegram IDs allowed to use the bot
  --location NAME        profile name shown in VPN clients (default: the domain)
  --port PORT            UDP port for Hysteria2 (default: 443)
  --lang ru|en           default bot language (default: ru)
  --first-key LABEL      label for the key created after install
  --no-ufw               do not touch the firewall
  --repo OWNER/NAME      source repository (default: $REPO)
  --ref REF              branch or tag to install (default: $REF)
  -y, --yes              non-interactive: use flags/env and defaults only
  --dry-run              install files, venv and config, but do not touch
                         hysteria, systemd or the firewall (used by CI)
  --uninstall            remove hyvpn from this server
  -h, --help             this text

Every option can also be given as an environment variable:
  HYVPN_DOMAIN, HYVPN_EMAIL, HYVPN_BOT_TOKEN, HYVPN_ADMIN_IDS, HYVPN_LOCATION,
  HYVPN_PORT, HYVPN_LANG, HYVPN_FIRST_KEY, HYVPN_UFW, HYVPN_YES, HYVPN_REPO,
  HYVPN_REF, HYVPN_DRY_RUN
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)     DOMAIN=${2:?}; shift 2 ;;
            --email)      EMAIL=${2:?}; shift 2 ;;
            --bot-token)  BOT_TOKEN=${2:?}; shift 2 ;;
            --admin-id|--admin-ids) ADMIN_IDS=${2:?}; shift 2 ;;
            --location)   LOCATION=${2:?}; shift 2 ;;
            --port)       PORT=${2:?}; shift 2 ;;
            --lang)       LANG_CHOICE=${2:?}; shift 2 ;;
            --first-key)  FIRST_KEY_LABEL=${2:?}; shift 2 ;;
            --no-ufw)     SETUP_UFW=no; shift ;;
            --repo)       REPO=${2:?}; shift 2 ;;
            --ref)        REF=${2:?}; shift 2 ;;
            -y|--yes)     ASSUME_YES=yes; shift ;;
            --dry-run)    DRY_RUN=yes; ASSUME_YES=yes; shift ;;
            --uninstall)  ACTION=uninstall; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            die "unknown option: $1 (see --help)" ;;
        esac
    done
}

# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root: sudo bash install.sh"
}

detect_os() {
    [[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) ok "${PRETTY_NAME:-$ID}" ;;
        *)
            warn "untested distribution: ${PRETTY_NAME:-${ID:-unknown}} (expected Ubuntu or Debian)"
            confirm "Continue anyway?" n || die "aborted"
            ;;
    esac
    command -v systemctl >/dev/null || die "systemd is required"
    [[ "$(uname -s)" == "Linux" ]] || die "Linux only"
}

check_ports() {
    command -v ss >/dev/null || return 0
    if ss -lunH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORT\$"; then
        warn "UDP/$PORT is already in use — Hysteria2 may fail to bind"
    fi
    if [[ "$EXISTING_INSTALL" == "no" ]] && ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE '[:.]80$'; then
        warn "TCP/80 is in use; ACME HTTP-01 validation may fail"
    fi
}

check_dns() {
    if dry_run; then info "DNS check: skipped (--dry-run)"; return 0; fi
    local resolved=""
    PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [[ -n "$PUBLIC_IP" ]] || PUBLIC_IP="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"

    if command -v getent >/dev/null; then
        resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
    fi
    if [[ -z "$resolved" ]]; then
        warn "could not resolve $DOMAIN — make sure its DNS record exists"
        confirm "Continue anyway?" n || die "aborted"
        return 0
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        info "$DOMAIN resolves to $resolved (could not detect this server's IP)"
        return 0
    fi
    if [[ "$resolved" == "$PUBLIC_IP" ]]; then
        ok "$DOMAIN → $resolved (this server)"
    else
        warn "$DOMAIN resolves to $resolved, but this server is $PUBLIC_IP"
        warn "Let's Encrypt will refuse to issue a certificate until DNS is fixed"
        confirm "Continue anyway?" n || die "aborted"
    fi
}

verify_bot_token() {
    if dry_run; then return 0; fi
    local response
    response="$(curl -fsS --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/getMe" 2>/dev/null || true)"
    if [[ -z "$response" ]]; then
        warn "could not reach the Telegram API — token not verified"
        return 0
    fi
    if [[ "$response" != *'"ok":true'* ]]; then
        warn "Telegram rejected this token"
        confirm "Continue anyway?" n || die "aborted"
        return 0
    fi
    BOT_USERNAME="$(printf '%s' "$response" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')"
    ok "bot @${BOT_USERNAME:-unknown}"
}

# --------------------------------------------------------------------------- #
# existing installation
# --------------------------------------------------------------------------- #

env_value() {
    # env_value FILE KEY
    [[ -r "$1" ]] || return 0
    sed -n "s/^$2=//p" "$1" | tail -n1
}

load_existing() {
    [[ -d "$INSTALL_DIR" || -d "$CONF_DIR" ]] || return 0
    EXISTING_INSTALL=yes

    local prev_domain prev_email prev_token prev_ids prev_location prev_port prev_lang prev_secret
    prev_domain="$(env_value "$CONF_DIR/.env.core" SERVER_DOMAIN)"
    prev_email="$(env_value "$CONF_DIR/.env.hysteria" ACME_EMAIL)"
    prev_token="$(env_value "$CONF_DIR/.env.bot" BOT_TOKEN)"
    prev_ids="$(env_value "$CONF_DIR/.env.bot" ALLOWED_TG_IDS)"
    prev_location="$(env_value "$CONF_DIR/.env.bot" LOCATION_NAME)"
    prev_port="$(env_value "$CONF_DIR/.env.core" SERVER_PORT)"
    prev_lang="$(env_value "$CONF_DIR/.env.bot" DEFAULT_LANG)"
    prev_secret="$(env_value "$CONF_DIR/.env.hysteria" TRAFFIC_STATS_SECRET)"

    DOMAIN="${DOMAIN:-$prev_domain}"
    EMAIL="${EMAIL:-$prev_email}"
    BOT_TOKEN="${BOT_TOKEN:-$prev_token}"
    ADMIN_IDS="${ADMIN_IDS:-$prev_ids}"
    LOCATION="${LOCATION:-$prev_location}"
    [[ -n "$prev_port" ]] && PORT="${PORT:-$prev_port}"
    [[ -n "$prev_lang" ]] && LANG_CHOICE="$prev_lang"
    STATS_SECRET="$prev_secret"

    ok "existing installation found — secrets, database and certificate are kept"
    if [[ -n "$prev_domain" ]]; then
        info "current domain: $prev_domain"
    fi
    # Never return non-zero: with `set -e` that would abort the install.
    return 0
}

# Prints "days" on stdout when a usable certificate for $1 exists.
cert_days_left() {
    local domain=$1 file days
    command -v openssl >/dev/null || return 1
    [[ -d "$ACME_DIR" ]] || return 1
    file="$(find "$ACME_DIR" -type f -name "*.crt" -path "*$domain*" 2>/dev/null | head -n1)"
    [[ -n "$file" ]] || file="$(find "$ACME_DIR" -type f -name "*.crt" 2>/dev/null | head -n1)"
    [[ -n "$file" ]] || return 1
    local end epoch now
    end="$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | cut -d= -f2)" || return 1
    [[ -n "$end" ]] || return 1
    epoch="$(date -d "$end" +%s 2>/dev/null)" || return 1
    now="$(date +%s)"
    days=$(( (epoch - now) / 86400 ))
    printf '%s' "$days"
}

check_certificate() {
    local days
    if days="$(cert_days_left "$DOMAIN")"; then
        if (( days > 0 )); then
            KEEP_CERT=yes
            ok "certificate for $DOMAIN is valid for another $days day(s) — not reissuing"
        else
            warn "certificate for $DOMAIN expired ${days#-} day(s) ago — Hysteria2 will renew it"
        fi
    elif [[ "$EXISTING_INSTALL" == "yes" ]]; then
        info "no certificate found yet — Hysteria2 will request one on start"
    fi

    local prev_domain
    prev_domain="$(env_value "$CONF_DIR/.env.hysteria" ACME_DOMAIN)"
    if [[ -n "$prev_domain" && "$prev_domain" != "$DOMAIN" ]]; then
        warn "domain changes from $prev_domain to $DOMAIN — a new certificate will be requested"
        KEEP_CERT=no
        confirm "Continue?" y || die "aborted"
    fi
}

# --------------------------------------------------------------------------- #
# questions
# --------------------------------------------------------------------------- #

ask_everything() {
    if interactive; then
        printf '\n%sОтветьте на несколько вопросов. Enter — принять значение в скобках.%s\n' "$DIM" "$RESET"
    fi
    ask DOMAIN "Домен сервера" "" valid_domain
    ask EMAIL "E-mail для Let's Encrypt" "admin@$DOMAIN" valid_email
    ask BOT_TOKEN "Токен Telegram-бота (@BotFather)" "" valid_token
    if [[ -z "$ADMIN_IDS" ]] && interactive; then
        info "Свой Telegram ID можно узнать у @userinfobot"
    fi
    ask ADMIN_IDS "Telegram ID администратора(ов), через запятую" "" valid_ids
    ADMIN_IDS="${ADMIN_IDS//[[:space:]]/}"
    ask LOCATION "Название сервера для клиентов" "$DOMAIN"
    ask PORT "UDP-порт Hysteria2" "443" valid_port
    choose LANG_CHOICE "Язык бота по умолчанию:" "ru:Русский" "en:English"
    if [[ "$SETUP_UFW" == "yes" ]] && interactive; then
        confirm "Настроить брандмауэр UFW (SSH + UDP/$PORT)?" y || SETUP_UFW=no
    fi
    if [[ -z "$FIRST_KEY_LABEL" && "$EXISTING_INSTALL" == "no" ]]; then
        FIRST_KEY_LABEL="my-phone"
        if interactive; then
            FIRST_KEY_LABEL=""
            ask FIRST_KEY_LABEL "Название первого ключа" "my-phone"
        fi
    fi
    case "$LANG_CHOICE" in ru|en) ;; *) die "unsupported language: $LANG_CHOICE" ;; esac
}

show_plan() {
    cat <<EOF

      ${BOLD}Что будет сделано${RESET}
      домен ................ $DOMAIN
      UDP-порт ............. $PORT
      имя для клиентов ..... $LOCATION
      админы бота .......... $ADMIN_IDS
      язык бота ............ $LANG_CHOICE
      каталог .............. $INSTALL_DIR
      сертификат ........... $([[ "$KEEP_CERT" == "yes" ]] && echo "существующий" || echo "получить через ACME")
      брандмауэр ........... $([[ "$SETUP_UFW" == "yes" ]] && echo "настроить UFW" || echo "не трогать")
EOF
    confirm "Продолжить?" y || die "aborted"
}

# --------------------------------------------------------------------------- #
# installation steps
# --------------------------------------------------------------------------- #

dry_run() { [[ "$DRY_RUN" == "yes" ]]; }

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    local packages=(curl ca-certificates openssl python3 python3-venv python3-pip sqlite3 iproute2 qrencode)
    [[ "$SETUP_UFW" == "yes" ]] && packages+=(ufw)
    apt-get install -y -qq "${packages[@]}" >/dev/null
    ok "packages installed"
}

install_hysteria() {
    if dry_run; then info "hysteria: skipped (--dry-run)"; return 0; fi
    if command -v hysteria >/dev/null; then
        ok "hysteria already installed ($(hysteria version 2>/dev/null | awk '/^Version/{print $2; exit}'))"
    else
        # Official installer; it also creates the "hysteria" system user.
        bash <(curl -fsSL https://get.hy2.sh/) >/dev/null
        command -v hysteria >/dev/null || die "hysteria installation failed"
        ok "hysteria installed"
    fi
    # The official unit is replaced by ours.
    systemctl disable --now hysteria-server.service >/dev/null 2>&1 || true
    id -u "$HYSTERIA_USER" >/dev/null 2>&1 || useradd --system --no-create-home \
        --shell /usr/sbin/nologin "$HYSTERIA_USER"
}

create_user_and_dirs() {
    id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system \
        --home "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
    # The hysteria user needs to traverse the state directory shared with hyvpn.
    usermod -a -G "$SERVICE_USER" "$HYSTERIA_USER" >/dev/null 2>&1 || true

    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$INSTALL_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"
    install -d -o root -g "$SERVICE_USER" -m 0750 "$CONF_DIR"
    install -d -o "$HYSTERIA_USER" -g "$SERVICE_USER" -m 0750 "$HYSTERIA_STATE_DIR"
    ok "user $SERVICE_USER and directories ready"
}

fetch_source() {
    if [[ -f "$SCRIPT_DIR/hy_core_app.py" && -d "$SCRIPT_DIR/core" ]]; then
        SOURCE_DIR="$SCRIPT_DIR"
        ok "installing from local checkout: $SOURCE_DIR"
        return
    fi
    TMP_DIR="$(mktemp -d)"
    info "downloading $REPO@$REF"
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" \
        | tar -xz -C "$TMP_DIR" --strip-components=1 \
        || die "could not download $REPO@$REF"
    [[ -f "$TMP_DIR/hy_core_app.py" ]] || die "downloaded archive looks wrong"
    SOURCE_DIR="$TMP_DIR"
    ok "source downloaded"
}

copy_source() {
    local item
    for item in core bot bin systemd hy_core_app.py hy-cli.py hysteria-server.yaml \
                requirements.txt pyproject.toml README.md; do
        [[ -e "$SOURCE_DIR/$item" ]] || continue
        rm -rf "$INSTALL_DIR/${item:?}"
        cp -a "$SOURCE_DIR/$item" "$INSTALL_DIR/"
    done
    find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 0750 "$INSTALL_DIR"
    ok "application files in $INSTALL_DIR"
}

setup_venv() {
    if [[ ! -x "$INSTALL_DIR/.venv/bin/python" ]]; then
        sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/.venv"
    fi
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q --upgrade pip wheel
    if ! sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q \
            -r "$INSTALL_DIR/requirements.txt"; then
        warn "full dependency install failed — retrying without QR support"
        grep -v '^qrcode' "$INSTALL_DIR/requirements.txt" >"$INSTALL_DIR/.requirements.min"
        chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.requirements.min"
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install -q \
            -r "$INSTALL_DIR/.requirements.min" || die "pip install failed"
        QR_SUPPORT=no
    fi
    ok "python environment ready"
}

write_env_files() {
    if [[ -z "$STATS_SECRET" ]]; then
        STATS_SECRET="$(openssl rand -hex 32)"
        info "generated a new Traffic Stats secret"
    else
        info "keeping the existing Traffic Stats secret"
    fi

    write_env "$CONF_DIR/.env.core" <<EOF
# hy-core — generated by install.sh
DATABASE_PATH=$DATA_DIR/hyvpn.sqlite3
CORE_HOST=127.0.0.1
CORE_PORT=8080

HYSTERIA_STATS_URL=http://127.0.0.1:9999
HYSTERIA_STATS_SECRET=$STATS_SECRET

POLL_INTERVAL_SECONDS=60
FLUSH_INTERVAL_SECONDS=600

SERVER_DOMAIN=$DOMAIN
SERVER_PORT=$PORT
LOCATION_NAME=$LOCATION

ACME_DIR=$ACME_DIR
CERT_STATUS_PATH=$CERT_STATUS_PATH
EOF

    write_env "$CONF_DIR/.env.bot" <<EOF
# hy-bot — generated by install.sh
BOT_TOKEN=$BOT_TOKEN
ALLOWED_TG_IDS=$ADMIN_IDS
DEFAULT_LANG=$LANG_CHOICE

DATABASE_PATH=$DATA_DIR/hyvpn.sqlite3
SERVER_DOMAIN=$DOMAIN
SERVER_PORT=$PORT
LOCATION_NAME=$LOCATION

HYSTERIA_STATS_URL=http://127.0.0.1:9999
HYSTERIA_STATS_SECRET=$STATS_SECRET

ACME_DIR=$ACME_DIR
CERT_STATUS_PATH=$CERT_STATUS_PATH
EOF

    write_env "$CONF_DIR/.env.hysteria" <<EOF
# hysteria-server — generated by install.sh
TRAFFIC_STATS_SECRET=$STATS_SECRET
ACME_DOMAIN=$DOMAIN
ACME_EMAIL=$EMAIL
EOF
    ok "configuration written to $CONF_DIR (0640 root:$SERVICE_USER)"
}

write_env() {
    local target=$1
    install -m 0640 -o root -g "$SERVICE_USER" /dev/null "$target"
    cat >"$target"
    chmod 0640 "$target"
    chown "root:$SERVICE_USER" "$target"
}

render_listen_port() {
    # The bundled template listens on :443; honour a custom port.
    if [[ "$PORT" != "443" ]]; then
        sed -i "s/^listen: :443$/listen: :$PORT/" "$INSTALL_DIR/hysteria-server.yaml"
    fi
}

install_units() {
    if dry_run; then info "systemd units: skipped (--dry-run)"; return 0; fi
    local unit
    for unit in "${UNITS[@]}"; do
        [[ -f "$SOURCE_DIR/systemd/$unit" ]] || continue
        install -m 0644 "$SOURCE_DIR/systemd/$unit" "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    ok "systemd units installed"
}

install_wrapper() {
    if [[ -f "$SOURCE_DIR/bin/hyvpn" ]]; then
        install -m 0755 "$SOURCE_DIR/bin/hyvpn" "$WRAPPER"
        ok "management command: hyvpn"
    fi
}

setup_firewall() {
    if dry_run; then info "firewall: skipped (--dry-run)"; return 0; fi
    [[ "$SETUP_UFW" == "yes" ]] || { info "firewall untouched"; return; }
    command -v ufw >/dev/null || { warn "ufw not available"; return; }

    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow "$PORT/udp" >/dev/null 2>&1 || true
    # ACME HTTP-01 needs TCP/80 reachable.
    ufw allow 80/tcp >/dev/null 2>&1 || true
    if ! ufw status | grep -q "^Status: active"; then
        ufw --force enable >/dev/null 2>&1 || warn "could not enable ufw"
    fi
    ok "ufw: 22/tcp, $PORT/udp, 80/tcp allowed"
}

start_services() {
    if dry_run; then info "service start: skipped (--dry-run)"; return 0; fi
    systemctl enable --now hy-core.service >/dev/null
    systemctl enable --now hysteria-server.service >/dev/null
    systemctl enable --now hy-bot.service >/dev/null
    systemctl enable --now hy-certwatch.timer >/dev/null 2>&1 || true
    systemctl restart hy-core.service hysteria-server.service hy-bot.service
    systemctl start hy-certwatch.service >/dev/null 2>&1 || true
    ok "services started"
}

wait_for_health() {
    if dry_run; then info "health check: skipped (--dry-run)"; return 0; fi
    local attempt
    for attempt in $(seq 1 30); do
        if curl -fsS --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
            ok "hy-core answers on 127.0.0.1:8080"
            break
        fi
        sleep 1
        if (( attempt == 30 )); then
            warn "hy-core did not answer in 30s — check: journalctl -u hy-core -n 50"
        fi
    done

    local unit
    for unit in hy-core hysteria-server hy-bot; do
        if systemctl is-active --quiet "$unit"; then
            ok "$unit is running"
        else
            warn "$unit is NOT running — check: journalctl -u $unit -n 50"
        fi
    done
}

key_count() {
    local db="$DATA_DIR/hyvpn.sqlite3"
    [[ -f "$db" ]] || { echo 0; return; }
    sqlite3 "$db" "SELECT COUNT(*) FROM keys;" 2>/dev/null || echo 0
}

create_first_key() {
    if dry_run; then info "first key: skipped (--dry-run)"; return 0; fi
    [[ -n "$FIRST_KEY_LABEL" ]] || return 0
    if [[ "$(key_count)" != "0" ]]; then
        info "keys already exist — not creating another one"
        return 0
    fi
    local output uri
    output="$(cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" \
        env PYTHONPATH="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" hy-cli.py \
        create-key --label "$FIRST_KEY_LABEL" 2>&1)" || {
            warn "could not create the first key:"
            printf '%s\n' "$output" >&2
            return 0
        }
    uri="$(printf '%s\n' "$output" | sed -n 's/^uri:[[:space:]]*//p')"
    printf '\n      %sПервый ключ%s (%s)\n\n' "$BOLD" "$RESET" "$FIRST_KEY_LABEL"
    printf '      %s\n\n' "$uri"
    if command -v qrencode >/dev/null && [[ -n "$uri" ]]; then
        qrencode -t ANSIUTF8 -m 2 "$uri" || true
    fi
}

summary() {
    local cert_note="—" days
    if days="$(cert_days_left "$DOMAIN")"; then
        cert_note="действует ещё $days дн."
    else
        cert_note="будет получен при первом подключении"
    fi

    cat <<EOF

$GREEN$BOLD  Готово!$RESET

  ${BOLD}Сервер${RESET}      $DOMAIN:$PORT/udp
  ${BOLD}Сертификат${RESET}  $cert_note
  ${BOLD}Бот${RESET}         ${BOT_USERNAME:+@$BOT_USERNAME }— напишите ему /start
  ${BOLD}Админы${RESET}      $ADMIN_IDS
  ${BOLD}QR-коды${RESET}     $([[ "$QR_SUPPORT" == "yes" ]] && echo "включены" || echo "недоступны (не установился Pillow)")

  ${BOLD}Управление${RESET}
    hyvpn status              состояние сервисов и сертификата
    hyvpn key add "Иван"      выдать ключ
    hyvpn key ls              список ключей
    hyvpn key limit <id> 50GB лимит трафика
    hyvpn logs bot            журнал бота
    hyvpn update              обновить до последней версии
    hyvpn uninstall           удалить

  ${DIM}Конфигурация: $CONF_DIR/.env.*  ·  база: $DATA_DIR/hyvpn.sqlite3${RESET}
EOF
}

# --------------------------------------------------------------------------- #
# uninstall
# --------------------------------------------------------------------------- #

do_uninstall() {
    banner
    printf '\n%sУдаление hyvpn%s\n' "$BOLD" "$RESET"
    confirm "Остановить и удалить сервисы hyvpn?" n || die "aborted"

    local unit
    for unit in "${UNITS[@]}"; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR" "$WRAPPER"
    ok "services and $INSTALL_DIR removed"

    if confirm "Удалить базу ключей и статистику ($DATA_DIR)?" n; then
        rm -rf "$DATA_DIR"
        ok "$DATA_DIR removed"
    else
        info "$DATA_DIR kept"
    fi
    if confirm "Удалить конфигурацию ($CONF_DIR)?" n; then
        rm -rf "$CONF_DIR"
        ok "$CONF_DIR removed"
    else
        info "$CONF_DIR kept"
    fi
    if confirm "Удалить сам Hysteria2 и его сертификаты?" n; then
        bash <(curl -fsSL https://get.hy2.sh/) --remove >/dev/null 2>&1 || \
            rm -f /usr/local/bin/hysteria
        rm -rf "$HYSTERIA_STATE_DIR"
        ok "hysteria removed"
    fi
    printf '\n%sГотово.%s\n' "$GREEN" "$RESET"
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

main() {
    parse_args "$@"
    require_root

    if [[ "$ACTION" == "uninstall" ]]; then
        do_uninstall
        return
    fi

    # Registered only for the install path: --help and --uninstall report
    # their own outcomes.
    trap 'on_error $LINENO' ERR

    # Registered only for the install path, so --help and --uninstall can
    # report their own outcome without a scary failure notice.
    trap 'on_error $LINENO' ERR

    banner
    step "Проверка системы"
    detect_os
    load_existing

    step "Настройка"
    ask_everything
    check_dns
    check_ports
    verify_bot_token
    check_certificate
    show_plan

    step "Установка пакетов"
    install_packages

    step "Установка Hysteria2"
    install_hysteria

    step "Пользователь и каталоги"
    create_user_and_dirs

    step "Загрузка исходников"
    fetch_source
    copy_source
    render_listen_port

    step "Python-окружение"
    setup_venv

    step "Конфигурация"
    write_env_files

    step "Сервисы"
    install_units
    install_wrapper

    step "Брандмауэр"
    setup_firewall

    step "Запуск"
    start_services
    wait_for_health
    create_first_key

    if dry_run; then
        ok "dry-run finished: files, venv and configuration are in place"
        return
    fi
    summary
}

main "$@"
