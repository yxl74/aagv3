#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install -e .

gradle -v

gradle -p java/soot-extractor jar

mvn -f FlowDroid/pom.xml -pl soot-infoflow-cmd -am package -DskipTests
