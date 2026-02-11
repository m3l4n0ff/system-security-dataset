#!/bin/bash
set -e

GATLING_HOME="$(pwd)/gatling-3.10.3"
DEPLOY_DIR="$(pwd)/../deploy/openproject"
LOGGING_DIR="$(pwd)/../deploy/openproject"

echo "OpenProject Security Dataset Generation"
echo ""


# CLEAN START: Delete old indices

echo "[CLEAN] Deleting old indices..."
curl -X DELETE "http://localhost:9201/openproject-car-*" 2>/dev/null || true
sleep 5


# EXPERIMENT 1: NORMAL USAGE

echo ""
echo "[1/5] NORMAL USAGE"
cd "$DEPLOY_DIR"
echo "   Applying normal labels..."
docker compose -f docker-compose.yml -f docker-compose.labels-normal.yml up -d web proxy
sleep 5

echo "   Restarting Filebeat to pick up labels..."
cd "$LOGGING_DIR"
docker compose -f docker-compose.logging.yml restart filebeat
sleep 10

echo "   Running simulation..."
cd "$GATLING_HOME"
JAVA_OPTS="-DbaseUrl=http://localhost:8080 -Dusers=10 -Dduration=60" \
  ./bin/gatling.sh -sf user-files/simulations -s openproject.NormalUsageSimulation -nr

echo "[OK] Normal usage complete"
sleep 30


# EXPERIMENT 2: T1078

echo ""
echo "[2/5] T1078 - CREDENTIAL STUFFING"
cd "$DEPLOY_DIR"
echo "   Applying T1078 labels..."
docker compose -f docker-compose.yml -f docker-compose.labels-t1078.yml up -d web proxy
sleep 5

echo "   Restarting Filebeat..."
cd "$LOGGING_DIR"
docker compose -f docker-compose.logging.yml restart filebeat
sleep 10

echo "   Running attack..."
cd "$GATLING_HOME"
JAVA_OPTS="-DbaseUrl=http://localhost:8080 -Diterations=20" \
  ./bin/gatling.sh -sf user-files/simulations -s openproject.T1078_CredentialStuffingSimulation -nr

echo "[OK] T1078 complete"
sleep 30


# EXPERIMENT 3: T1083

echo ""
echo "[3/5] T1083 - API RECONNAISSANCE"
cd "$DEPLOY_DIR"
echo "   Applying T1083 labels..."
docker compose -f docker-compose.yml -f docker-compose.labels-t1083.yml up -d web proxy
sleep 5

echo "   Restarting Filebeat..."
cd "$LOGGING_DIR"
docker compose -f docker-compose.logging.yml restart filebeat
sleep 10

echo "   Running attack..."
cd "$GATLING_HOME"
JAVA_OPTS="-DbaseUrl=http://localhost:8080" \
  ./bin/gatling.sh -sf user-files/simulations -s openproject.T1083_APIReconnaissanceSimulation -nr

echo "[OK] T1083 complete"
sleep 30


# EXPERIMENT 4: T1071

echo ""
echo "[4/5] T1071 - C2 BEACONING"
cd "$DEPLOY_DIR"
echo "   Applying T1071 labels..."
docker compose -f docker-compose.yml -f docker-compose.labels-t1071.yml up -d web proxy
sleep 5

echo "   Restarting Filebeat..."
cd "$LOGGING_DIR"
docker compose -f docker-compose.logging.yml restart filebeat
sleep 10

echo "   Running attack..."
cd "$GATLING_HOME"
JAVA_OPTS="-DbaseUrl=http://localhost:8080 -Dduration=600" \
  ./bin/gatling.sh -sf user-files/simulations -s openproject.T1071_C2BeaconingSimulation -nr

echo "[OK] T1071 complete"
sleep 30


# EXPERIMENT 5: T1498

echo ""
echo "[5/5] T1498 - APPLICATION DOS"
cd "$DEPLOY_DIR"
echo "   Applying T1498 labels..."
docker compose -f docker-compose.yml -f docker-compose.labels-t1498.yml up -d web proxy
sleep 5

echo "   Restarting Filebeat..."
cd "$LOGGING_DIR"
docker compose -f docker-compose.logging.yml restart filebeat
sleep 10

echo "   Running attack..."
cd "$GATLING_HOME"
JAVA_OPTS="-DbaseUrl=http://localhost:8080 -Dduration=60 -Dattackers=5" \
  ./bin/gatling.sh -sf user-files/simulations -s openproject.T1498_ApplicationDoSSimulation -nr

echo "[OK] T1498 complete"
sleep 30


# RESET TO NORMAL

echo ""
echo "Resetting to normal..."
cd "$DEPLOY_DIR"
docker compose -f docker-compose.yml -f docker-compose.labels-normal.yml up -d web proxy

echo ""
echo "ALL EXPERIMENTS COMPLETE!"
echo ""
echo "Verify:"
echo "  curl 'http://localhost:9201/openproject-car-*/_count?q=event.label:malicious' | jq"
echo "  curl 'http://localhost:9201/openproject-car-*/_count?q=event.label:normal' | jq"
echo ""
