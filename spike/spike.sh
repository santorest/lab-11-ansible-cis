#!/usr/bin/env bash
# Throwaway feasibility spike: oscap + SSG profile on the runner, rule list, baseline, guardrail trial.
set -euxo pipefail
cd "$(dirname "$0")/.."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner unzip \
  || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-utils unzip
oscap --version | head -3
bash scripts/get-ssg.sh
ds=out/ssg/ssg-ubuntu2404-ds.xml
profile=xccdf_org.ssgproject.content_profile_cis_level1_server
oscap info --profile "$profile" "$ds" | head -20
rc=0
time sudo oscap xccdf eval --profile "$profile" --results-arf out/before.xml --report out/before.html "$ds" > out/before.txt || rc=$?
echo "oscap exit $rc"
sudo chown "$(id -u):$(id -g)" out/before.xml out/before.html
for r in pass fail notapplicable notchecked error unknown; do echo "$r $(grep -cE "^Result\s+$r$" out/before.txt || true)"; done
python3 - <<'EOF'
import xml.etree.ElementTree as ET
ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
t = ET.parse("out/before.xml")
titles = {r.get("id"): (r.findtext("x:title", default="", namespaces=ns), r.get("severity", "")) for r in t.iterfind(".//x:Rule", ns)}
n = 0
with open("out/rules.tsv", "w") as f:
    for rr in t.iterfind(".//x:TestResult/x:rule-result", ns):
        res = rr.findtext("x:result", namespaces=ns)
        if res == "notselected":
            continue
        title, sev = titles.get(rr.get("idref"), ("", ""))
        f.write(f"{rr.get('idref')}\t{res}\t{sev}\t{title}\n")
        n += 1
print(n, "selected rules")
EOF
grep -iE "journald|rsyslog|audit|aide" out/rules.tsv | cut -f1,2 | sed 's/xccdf_org.ssgproject.content_rule_//' | head -80
# guardrail trial: the riskiest settings, then prove the runner still talks to GitHub
sudo apt-get install -y -qq ufw
for p in 53/udp 53/tcp 80/tcp 443/tcp 123/udp; do sudo ufw allow out "$p"; done
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw --force enable
sudo ufw status verbose
sudo sysctl -w net.ipv4.ip_forward=0
printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n' | sudo tee /etc/sudoers.d/99-spike
sudo chmod 0440 /etc/sudoers.d/99-spike
sudo visudo -cf /etc/sudoers.d/99-spike
sudo systemctl reload ssh || sudo systemctl reload sshd || echo "no ssh service"
curl -fsS -o /dev/null -w "github api %{http_code}\n" https://api.github.com
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq aide aide-common
start=$(date +%s)
sudo timeout 900 aideinit -y -f > /dev/null 2>&1 && echo "aideinit ok" || echo "aideinit did not finish (rc $?)"
echo "aideinit seconds: $(( $(date +%s) - start ))"
echo "SPIKE DONE"
