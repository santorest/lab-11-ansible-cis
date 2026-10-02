#!/usr/bin/env bash
# Download the pinned SCAP Security Guide release, verify its SHA-512 and extract the Ubuntu 24.04 datastream.
set -euo pipefail
cd "$(dirname "$0")/.."
read_policy() { python3 -c "import sys,yaml; print(yaml.safe_load(open('policy/policy.yml'))['ssg'][sys.argv[1]])" "$1"; }
url=$(read_policy url)
sum=$(read_policy sha512)
ds=$(read_policy datastream)
mkdir -p out/ssg
[ -f out/ssg/ssg.zip ] || curl -fsSL --retry 3 -o out/ssg/ssg.zip "$url"
echo "$sum  out/ssg/ssg.zip" | sha512sum -c -
unzip -o -j -q out/ssg/ssg.zip "*/$ds" -d out/ssg
ls -l "out/ssg/$ds"
