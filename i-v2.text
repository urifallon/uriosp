sudo tee /usr/local/bin/uriosp >/dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail

APP="uriosp"

ETC="/etc/uriosp"
PROFILES="$ETC/profile"
ACTIVE="$ETC/active"

LOGDIR="/var/log/uriosp-logs"
LOGFILE="$LOGDIR/uriosp.log"

GROUP="uriosp"
DEFAULT_CLOUD="${URIOSP_DEFAULT_CLOUD:-openstack}"
STRICT_CLOUD="${URIOSP_STRICT_CLOUD:-1}"  # 1=block if YAML missing DEFAULT_CLOUD, 0=warn
SESSION_PASS_ENV="URIOSP_OS_PASSWORD"

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing: $1"; }

log(){
  local level="$1"; shift
  { echo "$(date -Is) level=$level user=${SUDO_USER:-$USER} msg=$*"; } >> "$LOGFILE" 2>/dev/null || true
}

ensure_layout_root(){
  [[ $EUID -eq 0 ]] || die "This action requires root. Use sudo."
  groupadd -f "$GROUP"
  mkdir -p "$ETC" "$PROFILES" "$LOGDIR"
  touch "$ACTIVE" "$LOGFILE"
  chown -R root:"$GROUP" "$ETC" "$LOGDIR"
  chmod 0750 "$ETC" "$PROFILES"
  chmod 0770 "$LOGDIR"
  chmod 0640 "$ACTIVE"
  chmod 0660 "$LOGFILE"
}

cfg_path(){ echo "$PROFILES/$1.yaml"; }

has_default_cloud(){
  local cfg="$1" cloud="$2"
  awk -v want="$cloud" '
    /^clouds:[[:space:]]*$/ {inside=1; next}
    inside && /^[[:space:]]+[A-Za-z0-9_.-]+:[[:space:]]*$/ {
      key=$1; sub(/:$/, "", key);
      if (key == want) { found=1; exit }
    }
    END { exit(found?0:1) }
  ' "$cfg"
}

get_active(){
  [[ -r "$ACTIVE" ]] || die "No active profile. Run: sudo $APP config <clouds.yaml>"
  local p; p="$(tr -d '[:space:]' < "$ACTIVE")"
  [[ -n "$p" ]] || die "Active profile empty. Re-run config."
  echo "$p"
}

require_session_password(){
  local val="${!SESSION_PASS_ENV-}"
  [[ -n "$val" ]] || die "No session password loaded. Run: eval \"\$($APP auth)\""
}

run_openstack(){
  need openstack
  local profile cfg
  profile="$(get_active)"
  cfg="$(cfg_path "$profile")"
  [[ -r "$cfg" ]] || die "Profile not readable: $cfg (add your user to group '$GROUP')"

  if ! has_default_cloud "$cfg" "$DEFAULT_CLOUD"; then
    log "WARN" "RUN profile=$profile note=missing_default_cloud cfg=$cfg"
    if [[ "$STRICT_CLOUD" == "1" ]]; then
      die "Active profile YAML missing clouds: $DEFAULT_CLOUD:. Refusing to run."
    else
      echo "WARNING: Active profile YAML missing clouds: $DEFAULT_CLOUD:. This will likely fail." >&2
    fi
  fi

  require_session_password

  OS_CLIENT_CONFIG_FILE="$cfg" \
  OS_CLOUD="$DEFAULT_CLOUD" \
  OS_PASSWORD="${!SESSION_PASS_ENV}" \
  openstack "$@"
}

cmd_auth(){
  local pw
  read -r -s -p "OpenStack Password (session-only): " pw
  echo >&2
  [[ -n "$pw" ]] || die "Empty password."
  printf 'export %s=%q\n' "$SESSION_PASS_ENV" "$pw"
  log "INFO" "AUTH loaded session password (not persisted)"
}

cmd_config(){
  local src="${1:-}"
  [[ -n "$src" ]] || die "Usage: $APP config <clouds.yaml>"
  [[ -f "$src" ]] || die "File not found: $src"

  ensure_layout_root

  local base profile dst
  base="$(basename "$src")"
  profile="${base%.*}"
  dst="$(cfg_path "$profile")"

  cp -f "$src" "$dst"
  chown root:"$GROUP" "$dst"
  chmod 0640 "$dst"

  if ! has_default_cloud "$dst" "$DEFAULT_CLOUD"; then
    log "WARN" "CONFIG profile=$profile note=missing_default_cloud file=$dst"
    if [[ "$STRICT_CLOUD" == "1" ]]; then
      die "YAML does not contain clouds: $DEFAULT_CLOUD:. Fix the file or set URIOSP_DEFAULT_CLOUD."
    else
      echo "WARNING: YAML missing clouds: $DEFAULT_CLOUD:. '$APP os' may fail." >&2
    fi
  fi

  echo "$profile" > "$ACTIVE"
  chown root:"$GROUP" "$ACTIVE"
  chmod 0640 "$ACTIVE"

  log "INFO" "CONFIG ok profile=$profile dst=$dst"
  echo "OK: stored profile '$profile' -> $dst"
  echo "Active profile: $profile"
  echo "Default cloud: $DEFAULT_CLOUD"
}

cmd_use(){
  local profile="${1:-}"
  [[ -n "$profile" ]] || die "Usage: $APP use <profile>"
  [[ -r "$(cfg_path "$profile")" ]] || die "Profile not found or not readable: $(cfg_path "$profile")"
  echo "$profile" | sudo tee "$ACTIVE" >/dev/null
  log "INFO" "USE profile=$profile"
  echo "Active profile: $profile"
}

cmd_list(){
  [[ -d "$PROFILES" ]] || { echo "(no profiles)"; exit 0; }
  ls -1 "$PROFILES" 2>/dev/null | sed -n 's/\.yaml$//p' || true
}

cmd_os(){
  log "INFO" "OS cmd=openstack $*"
  run_openstack "$@"
}

# ---------- inventory subcommands ----------

cmd_inventory_projects(){
  need python3
  need mktemp

  local profile cfg
  profile="$(get_active)"
  cfg="$(cfg_path "$profile")"
  [[ -r "$cfg" ]] || die "Profile not readable: $cfg (add your user to group '$GROUP')"
  require_session_password

  local cfg_json_file proj_json_file ra_json_file
  cfg_json_file="$(mktemp)"
  proj_json_file="$(mktemp)"
  ra_json_file="$(mktemp)"
  # IMPORTANT: expand filenames now; do NOT reference locals later (set -u safe)
  trap 'rm -f "'"$cfg_json_file"'" "'"$proj_json_file"'" "'"$ra_json_file"'" 2>/dev/null || true' RETURN

  run_openstack configuration show -f json >"$cfg_json_file" 2>/dev/null || printf '{}' >"$cfg_json_file"
  run_openstack project list -f json >"$proj_json_file"
  run_openstack role assignment list --names -f json >"$ra_json_file" 2>/dev/null || printf '[]' >"$ra_json_file"

  OS_CLIENT_CONFIG_FILE="$cfg" \
  OS_CLOUD="$DEFAULT_CLOUD" \
  OS_PASSWORD="${!SESSION_PASS_ENV}" \
  python3 - "$profile" "$DEFAULT_CLOUD" "$cfg" "$cfg_json_file" "$proj_json_file" "$ra_json_file" <<'PY'
import sys, json, re, shutil, datetime, os

profile, cloud = sys.argv[1], sys.argv[2]
clouds_yaml_path = sys.argv[3]
cfg_path, proj_path, ra_path = sys.argv[4], sys.argv[5], sys.argv[6]

term_cols = shutil.get_terminal_size((120, 20)).columns

def load_json(path, default):
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:
    return default

cfg = load_json(cfg_path, {})
projects = load_json(proj_path, [])
ra = load_json(ra_path, [])

def parse_clouds_yaml_auth_url(path, want_cloud):
  in_clouds = False
  target_indent = None
  auth_indent = None
  in_target = False
  in_auth = False
  auth_url = ""
  region = ""
  domain = ""

  try:
    with open(path, "r", encoding="utf-8") as f:
      for raw in f:
        line = raw.split("#", 1)[0].rstrip("\n")
        if not line.strip():
          continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()

        if s == "clouds:":
          in_clouds = True
          in_target = in_auth = False
          target_indent = auth_indent = None
          continue

        if in_clouds and indent == 2 and s.endswith(":"):
          key = s[:-1].strip()
          in_target = (key == want_cloud)
          target_indent = 2 if in_target else None
          in_auth = False
          auth_indent = None
          continue

        if in_target and target_indent is not None:
          if indent <= target_indent:
            in_target = in_auth = False
            continue

          if s == "auth:" and indent == target_indent + 2:
            in_auth = True
            auth_indent = indent
            continue

          if in_auth and auth_indent is not None:
            if indent <= auth_indent:
              in_auth = False
            else:
              if s.startswith("auth_url:"):
                auth_url = s.split(":", 1)[1].strip().strip('"').strip("'")
              elif s.startswith("user_domain_name:") and not domain:
                domain = s.split(":", 1)[1].strip().strip('"').strip("'")

          if s.startswith("region_name:") and indent == target_indent + 2 and not region:
            region = s.split(":", 1)[1].strip().strip('"').strip("'")
          if s.startswith("user_domain_name:") and indent == target_indent + 2 and not domain:
            domain = s.split(":", 1)[1].strip().strip('"').strip("'")

    return auth_url, region, domain
  except Exception:
    return "", "", ""

region = cfg.get("region_name") or cfg.get("region") or ""
domain = cfg.get("user_domain_name") or cfg.get("project_domain_name") or cfg.get("domain_name") or ""
auth_url = cfg.get("auth_url") or ""

# Fallback from clouds.yaml if missing
if (not auth_url) or (not region) or (not domain):
  y_auth_url, y_region, y_domain = parse_clouds_yaml_auth_url(clouds_yaml_path, cloud)
  auth_url = auth_url or y_auth_url
  region = region or y_region
  domain = domain or y_domain

endpoint = ""
m = re.match(r"^(https?://[^/]+)", auth_url or "")
if m:
  endpoint = m.group(1)
  endpoint = re.sub(r":5000$", "", endpoint)

# Users per project NAME (role assignment --names gives Project=Name)
users_by_pname = {}
for row in ra:
  pname = row.get("Project") or row.get("project") or ""
  user = row.get("User") or row.get("user") or ""
  if not pname or not user:
    continue
  users_by_pname.setdefault(pname, [])
  if user not in users_by_pname[pname]:
    users_by_pname[pname].append(user)

def status_flag(p):
  v = p.get("Enabled", p.get("enabled", None))
  if v in (True, "True", "true", "enabled", "Enabled", "YES", "Yes", "yes"):
    return "E"
  if v in (False, "False", "false", "disabled", "Disabled", "NO", "No", "no"):
    return "D"
  return ""

headers = ["Region","Domain","Endpoint","ProjectName","ProjectID","Status","UsersTop5"]
rows = []
for p in projects:
  pid = str(p.get("ID") or p.get("id") or "")
  pname = str(p.get("Name") or p.get("name") or "")
  users = ",".join(users_by_pname.get(pname, [])[:5])
  rows.append([region, domain, endpoint, pname, pid, status_flag(p), users])

def col_widths(headers, rows):
  w = [len(h) for h in headers]
  for r in rows:
    for i, c in enumerate(r):
      w[i] = max(w[i], len(c))
  return w

w = col_widths(headers, rows)
sep = "  "
def fmt_row(r):
  return sep.join(r[i].ljust(w[i]) for i in range(len(w)))

title = f"URIOSP INVENTORY PROJECTS | profile={profile} | cloud={cloud} | region={region} | endpoint={endpoint} | time={datetime.datetime.now().isoformat(timespec='seconds')}"
print(title)
print("=" * max(term_cols, len(title)))

hdr_line = fmt_row(headers)
print(hdr_line)
print("-" * max(term_cols, len(hdr_line)))

for r in rows:
  print(fmt_row(r))
PY
}

cmd_inventory_vms(){
  need python3
  need mktemp

  local profile cfg
  profile="$(get_active)"
  cfg="$(cfg_path "$profile")"
  [[ -r "$cfg" ]] || die "Profile not readable: $cfg (add your user to group '$GROUP')"
  require_session_password

  local proj_json_file net_json_file srv_json_file
  proj_json_file="$(mktemp)"
  net_json_file="$(mktemp)"
  srv_json_file="$(mktemp)"
  # IMPORTANT: expand filenames now; do NOT reference locals later (set -u safe)
  trap 'rm -f "'"$proj_json_file"'" "'"$net_json_file"'" "'"$srv_json_file"'" 2>/dev/null || true' RETURN

  run_openstack project list -f json >"$proj_json_file"
  run_openstack network list -f json >"$net_json_file" 2>/dev/null || printf '[]' >"$net_json_file"
  run_openstack server list --all-projects -f json >"$srv_json_file"

  OS_CLIENT_CONFIG_FILE="$cfg" \
  OS_CLOUD="$DEFAULT_CLOUD" \
  OS_PASSWORD="${!SESSION_PASS_ENV}" \
  python3 - "$profile" "$DEFAULT_CLOUD" "$proj_json_file" "$net_json_file" "$srv_json_file" <<'PY'
import sys, json, subprocess, re, ast, shutil, datetime

profile, cloud = sys.argv[1], sys.argv[2]
proj_path, net_path, srv_path = sys.argv[3], sys.argv[4], sys.argv[5]

term_cols = shutil.get_terminal_size((120, 20)).columns

def load_json(path, default):
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:
    return default

projects = load_json(proj_path, [])
nets = load_json(net_path, [])
servers = load_json(srv_path, [])

proj_name_by_id = {}
for p in projects:
  pid = p.get("ID") or p.get("id")
  name = p.get("Name") or p.get("name") or ""
  if pid:
    proj_name_by_id[str(pid)] = str(name)

net_id_by_name = {}
for n in nets:
  name = n.get("Name") or n.get("name")
  nid = n.get("ID") or n.get("id")
  if name and nid:
    net_id_by_name[str(name)] = str(nid)

def sh_json(cmd):
  r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  if r.returncode != 0:
    return {}
  try:
    return json.loads(r.stdout)
  except Exception:
    return {}

def power_state_str(val):
  m = {0:"NOSTATE",1:"RUNNING",3:"PAUSED",4:"SHUTDOWN",6:"CRASHED",7:"SUSPENDED"}
  try:
    return m.get(int(val), str(val))
  except Exception:
    return str(val) if val is not None else ""

def dedup(seq):
  out=[]
  for x in seq:
    if x and x not in out:
      out.append(x)
  return out

def parse_networks_pairs(nets_val):
  pairs=[]
  if nets_val is None:
    return pairs

  if isinstance(nets_val, dict):
    for k, v in nets_val.items():
      if isinstance(v, list):
        for ip in v:
          if isinstance(ip, str) and ip:
            pairs.append((ip, str(k)))
      elif isinstance(v, str) and v:
        pairs.append((v, str(k)))
    return pairs

  s = str(nets_val).strip()
  if not s:
    return pairs

  if s.startswith("{") and s.endswith("}"):
    try:
      d = ast.literal_eval(s)
      if isinstance(d, dict):
        return parse_networks_pairs(d)
    except Exception:
      pass

  parts = [p.strip() for p in s.split(",") if p.strip()]
  for p in parts:
    if "=" in p:
      k, v = p.split("=", 1)
      k = k.strip()
      v = v.strip()
      for ip in re.split(r"[;\s]+", v):
        ip = ip.strip()
        if ip:
          pairs.append((ip, k))

  if not pairs:
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-f:]{2,}", s, flags=re.I)
    for ip in ips:
      pairs.append((ip, ""))

  out=[]
  for ip, nn in pairs:
    if (ip, nn) not in out:
      out.append((ip, nn))
  return out

def pairs_from_addresses(addresses):
  pairs=[]
  if isinstance(addresses, dict):
    for net_name, lst in addresses.items():
      if isinstance(lst, list):
        for it in lst:
          if isinstance(it, dict) and it.get("addr"):
            pairs.append((it["addr"], net_name))
  out=[]
  for ip, nn in pairs:
    if (ip, nn) not in out:
      out.append((ip, nn))
  return out

headers = ["ProjectName","ProjectID","InstanceName","InstanceID","Volume","IP","NetworkName","NetworkID","Status","PowerState"]

all_lines = []
separators = []

for row in servers:
  sid = row.get("ID") or row.get("id")
  if not sid:
    continue
  sid = str(sid)

  sname = str(row.get("Name") or row.get("name") or "")
  status = str(row.get("Status") or row.get("status") or "")

  ip_pairs = parse_networks_pairs(row.get("Networks") or row.get("networks") or "")

  js = sh_json(["openstack","server","show",sid,"-f","json"])
  pid = str(js.get("project_id") or js.get("tenant_id") or "")
  pname = proj_name_by_id.get(pid, "") if pid else ""
  pstate = power_state_str(js.get("OS-EXT-STS:power_state") or js.get("power_state"))

  vols = js.get("volumes_attached") or []
  vol_ids=[]
  if isinstance(vols, list):
    for it in vols:
      if isinstance(it, dict) and it.get("id"):
        vol_ids.append(str(it["id"]))
  vol_ids = dedup(vol_ids)

  if not ip_pairs:
    ip_pairs = pairs_from_addresses(js.get("addresses") or {})

  max_len = max(len(vol_ids), len(ip_pairs), 1)

  for i in range(max_len):
    vol = vol_ids[i] if i < len(vol_ids) else ""
    pair = ip_pairs[i] if i < len(ip_pairs) else ("","")
    ip = pair[0] or ""
    net_name = pair[1] or ""
    net_id = net_id_by_name.get(net_name, "") if net_name else ""

    if i == 0:
      all_lines.append([pname, pid, sname, sid, vol, ip, net_name, net_id, status, str(pstate)])
    else:
      all_lines.append(["","","","", vol, ip, net_name, net_id, "", ""])

  separators.append(len(all_lines))

w = [len(h) for h in headers]
for r in all_lines:
  for i, c in enumerate(r):
    w[i] = max(w[i], len(c))

sep = "  "
def fmt_row(r):
  return sep.join(r[i].ljust(w[i]) for i in range(len(w)))

title = f"URIOSP INVENTORY VMS | profile={profile} | cloud={cloud} | time={datetime.datetime.now().isoformat(timespec='seconds')}"
print(title)
print("=" * max(term_cols, len(title)))

hdr_line = fmt_row(headers)
print(hdr_line)
print("-" * max(term_cols, len(hdr_line)))

sep_line = "-" * max(term_cols, len(hdr_line))
end_set = set(separators)

for idx, r in enumerate(all_lines, start=1):
  print(fmt_row(r))
  if idx in end_set:
    print(sep_line)
PY
}

cmd_inventory(){
  local sub="${1:-}"
  shift || true
  case "$sub" in
    projects) log "INFO" "INVENTORY projects"; cmd_inventory_projects "$@" ;;
    vms)      log "INFO" "INVENTORY vms";      cmd_inventory_vms "$@" ;;
    ""|-h|--help|help)
      cat <<EOF
Usage:
  $APP inventory projects
  $APP inventory vms
EOF
      ;;
    *) die "Unknown inventory subcommand: $sub (use: projects|vms)" ;;
  esac
}

cmd_logs(){
  [[ -r "$LOGFILE" ]] || { echo "(no logs yet or no permission)"; exit 0; }
  tail -n 200 "$LOGFILE"
}

usage(){
  cat <<EOF
$APP - OpenStack ops CLI (default cloud: $DEFAULT_CLOUD)

Session auth (no password stored in YAML):
  eval "\$($APP auth)"

Commands:
  sudo $APP config <clouds.yaml>
  $APP list
  $APP use <profile>
  $APP auth
  $APP os <openstack ...>
  $APP inventory projects
  $APP inventory vms
  $APP logs
EOF
}

case "${1:-}" in
  auth) shift; cmd_auth ;;
  config) shift; cmd_config "$@" ;;
  list) shift; cmd_list ;;
  use) shift; cmd_use "$@" ;;
  os) shift; cmd_os "$@" ;;
  inventory|inv) shift; cmd_inventory "$@" ;;
  logs) shift; cmd_logs ;;
  -h|--help|help|"") usage ;;
  *) die "Unknown command: $1 (use --help)" ;;
esac
SH

sudo chmod +x /usr/local/bin/uriosp



# Idempotent permission bootstrap
sudo groupadd -f uriosp
sudo mkdir -p /etc/uriosp/profile /var/log/uriosp-logs
sudo touch /etc/uriosp/active /var/log/uriosp-logs/uriosp.log
sudo chown -R root:uriosp /etc/uriosp /var/log/uriosp-logs
sudo chmod 0750 /etc/uriosp /etc/uriosp/profile
sudo chmod 0640 /etc/uriosp/active
sudo chmod 0770 /var/log/uriosp-logs
sudo chmod 0660 /var/log/uriosp-logs/uriosp.log
