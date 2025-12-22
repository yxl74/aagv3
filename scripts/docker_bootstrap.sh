#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

gradle -v

gradle -p java/soot-extractor jar

FLOWDROID_BUILD_MODE="${FLOWDROID_BUILD_MODE:-release}"
FLOWDROID_TAG="${FLOWDROID_TAG:-v2.14.1}"

if [[ "${FLOWDROID_BUILD_MODE}" == "release" ]]; then
  tmpdir="$(mktemp -d)"
  git clone --depth 1 --branch "${FLOWDROID_TAG}" https://github.com/secure-software-engineering/FlowDroid.git "${tmpdir}"
  mvn -f "${tmpdir}/pom.xml" -pl soot-infoflow-cmd -am package -DskipTests
  mkdir -p FlowDroid/soot-infoflow-cmd/target
  cp "${tmpdir}/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar" \
    FlowDroid/soot-infoflow-cmd/target/
else
  mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
fi
