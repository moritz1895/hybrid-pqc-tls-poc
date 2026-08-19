#!/usr/bin/env bash
# Runs the hybrid PQC TLS demo natively on Linux, no Docker.
#
# Usage:
#   ./run.sh              # default (software, BCJSSE) backend
#   ./run.sh ibm-cca       # IBM-CCA hardware backend - fails fast outside real z/OS/ICSF
#   ./run.sh --rebuild      # force "mvn clean package -DskipTests" before running
#   ./run.sh --rebuild ibm-cca
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v java >/dev/null 2>&1; then
    echo "error: 'java' not found on PATH. Install a Java 25 JDK first." >&2
    exit 1
fi

JAVA_VERSION_LINE="$(java -version 2>&1 | head -n 1)"
if [[ ! "$JAVA_VERSION_LINE" =~ \"25(\.|\")|version\ 25 ]]; then
    echo "error: Java 25 required, found: $JAVA_VERSION_LINE" >&2
    exit 1
fi

REBUILD=false
PROFILE=""
for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=true ;;
        ibm-cca) PROFILE="ibm-cca" ;;
        *)
            echo "error: unknown argument '$arg' (expected 'ibm-cca' and/or '--rebuild')" >&2
            exit 1
            ;;
    esac
done

JAR="$(ls target/hybrid-pqc-tls-poc-*.jar 2>/dev/null | grep -v sources | head -n 1 || true)"

if [[ "$REBUILD" == true || -z "$JAR" ]]; then
    if ! command -v mvn >/dev/null 2>&1; then
        echo "error: 'mvn' not found on PATH. Install Maven to build the jar first." >&2
        exit 1
    fi
    echo "Building jar (mvn clean package -DskipTests)..."
    mvn clean package -DskipTests
    JAR="$(ls target/hybrid-pqc-tls-poc-*.jar 2>/dev/null | grep -v sources | head -n 1)"
fi

if [[ -z "$JAR" ]]; then
    echo "error: no jar found in target/ after build" >&2
    exit 1
fi

if [[ -n "$PROFILE" ]]; then
    echo "Running $JAR (profile: $PROFILE)..."
    exec java -jar "$JAR" "--spring.profiles.active=$PROFILE"
else
    echo "Running $JAR (default software backend)..."
    exec java -jar "$JAR"
fi
