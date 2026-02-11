#!/bin/bash
set -e

GATLING_HOME="/home/kraken/Code/System_Security/tests/gatling-3.10.3"
DEPLOY_DIR="/home/kraken/Code/System_Security/deploy/openproject"

run_experiment() {
  local name="$1"
  local labels_file="$2"
  local simulation="$3"
  local java_opts="$4"

  echo ""
  echo "=========================================="
  echo " $name"
  echo "=========================================="

  echo "  Applying labels..."
  cd "$DEPLOY_DIR"
  docker compose -f docker-compose.yml -f "$labels_file" up -d web proxy
  sleep 5

  echo "  Restarting Filebeat..."
  docker compose -f docker-compose.logging.yml restart filebeat
  sleep 10

  echo "  Running simulation..."
  cd "$GATLING_HOME"
  JAVA_OPTS="$java_opts" ./bin/gatling.sh -rm local -sf user-files/simulations -s "$simulation" -nr

  echo "  Done. Waiting 30s for log ingestion..."
  sleep 30

  # Show count
  COUNT=$(curl -s "http://localhost:9201/openproject-car-*/_count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "?")
  echo "  Total events so far: $COUNT"
}

echo "=== OpenProject Security Dataset Generation ==="

# Experiment 1: Normal usage
run_experiment \
  "[1/8] NORMAL USAGE" \
  "docker-compose.labels-normal.yml" \
  "openproject.NormalUsageSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dusers=10 -Dduration=60"

# Experiment 2: T1078 Credential Stuffing
run_experiment \
  "[2/8] T1078 - CREDENTIAL STUFFING" \
  "docker-compose.labels-t1078.yml" \
  "openproject.T1078_CredentialStuffingSimulation" \
  "-DbaseUrl=http://localhost:8080 -Diterations=20"

# Experiment 3: T1083 API Reconnaissance
run_experiment \
  "[3/8] T1083 - API RECONNAISSANCE" \
  "docker-compose.labels-t1083.yml" \
  "openproject.T1083_APIReconnaissanceSimulation" \
  "-DbaseUrl=http://localhost:8080"

# Experiment 4: T1071 C2 Beaconing
run_experiment \
  "[4/8] T1071 - C2 BEACONING" \
  "docker-compose.labels-t1071.yml" \
  "openproject.T1071_C2BeaconingSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dduration=120"

# Experiment 5: T1498 Application DoS
run_experiment \
  "[5/8] T1498 - APPLICATION DOS" \
  "docker-compose.labels-t1498.yml" \
  "openproject.T1498_ApplicationDoSSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dduration=60 -Dattackers=5"

# Experiment 6: T1190 SQL Injection / XSS
run_experiment \
  "[6/8] T1190 - SQL INJECTION / XSS" \
  "docker-compose.labels-t1190.yml" \
  "openproject.T1190_SQLiXSSSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dduration=180"

# Experiment 7: T1595 Vulnerability Scanning
run_experiment \
  "[7/8] T1595 - VULNERABILITY SCANNING" \
  "docker-compose.labels-t1595.yml" \
  "openproject.T1595_VulnScanningSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dduration=180"

# Experiment 8: T1548 Privilege Escalation / IDOR
run_experiment \
  "[8/8] T1548 - PRIVILEGE ESCALATION / IDOR" \
  "docker-compose.labels-t1548.yml" \
  "openproject.T1548_PrivilegeEscalationSimulation" \
  "-DbaseUrl=http://localhost:8080 -Dduration=180"

# Reset to normal
echo ""
echo "=== Resetting to normal labels ==="
cd "$DEPLOY_DIR"
docker compose -f docker-compose.yml -f docker-compose.labels-normal.yml up -d web proxy

echo ""
echo "=== ALL EXPERIMENTS COMPLETE ==="
FINAL=$(curl -s "http://localhost:9201/openproject-car-*/_count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "?")
echo "Total events: $FINAL"
