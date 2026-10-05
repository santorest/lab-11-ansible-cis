#!/usr/bin/env bash
# The whole cycle on this machine: SSG -> scan -> harden -> harden again -> scan -> report -> gate.
# Run it on a disposable Ubuntu 24.04 host only (a CI runner or a throwaway VM): it hardens the machine it runs on.
set -euo pipefail
cd "$(dirname "$0")/.."
policy() { python3 -c "import sys,yaml; print(yaml.safe_load(open('policy/policy.yml'))['ssg'][sys.argv[1]])" "$1"; }
profile=$(policy profile)
ds="out/ssg/$(policy datastream)"
mkdir -p out
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner unzip
bash scripts/get-ssg.sh
scan() {  # oscap exits 2 when rules fail: expected; any other code is an error
  local rc=0
  # shellcheck disable=SC2024  # the redirect runs as the user on purpose: out/ is the user's, only oscap needs root
  sudo oscap xccdf eval --profile "$profile" --results-arf "out/$1.xml" --report "out/$1.html" "$ds" \
    > "out/$1.txt" || rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    echo "oscap failed with exit code $rc" >&2
    exit 2
  fi
  sudo chown "$(id -u):$(id -g)" "out/$1.xml" "out/$1.html"
}
ansible-galaxy collection install -r requirements.yml -p .ansible/collections
# The exceptions and tunables must reach the play, not only cisreport (Ansible reads group_vars next to the inventory)
ansible-inventory --host localhost \
  | python3 -c "import json, sys; sys.exit(0 if json.load(sys.stdin).get('cis_exceptions') else 'group_vars not loaded')"
scan before
ansible-playbook playbooks/harden.yml | tee out/first-run.log
ansible-playbook playbooks/harden.yml | tee out/second-run.log
scan after
cisreport report --policy policy/policy.yml --controls policy/controls.yml --group-vars inventory/group_vars/all.yml \
  --before out/before.xml --after out/after.xml --second-run out/second-run.log --out-dir out \
  --meta "run=${GITHUB_RUN_ID:-local}"
cisreport gate --results out/results.json
