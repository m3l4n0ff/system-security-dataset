#!/bin/bash

echo "════════════════════════════════════════════════════════════"
echo "   OPENPROJECT SECURITY DATASET - PROJECT STATUS CHECK"
echo "════════════════════════════════════════════════════════════"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Docker services
echo "[1]  INFRASTRUCTURE STATUS"
echo "─────────────────────────────────────────────────────────────"

cd ~/Code/System_Security/deploy/openproject

echo "OpenProject Application:"
docker compose ps | grep -E "web|proxy|db|cache" | while read line; do
  if echo "$line" | grep -q "Up"; then
    echo -e "  ${GREEN}[OK]${NC} $(echo $line | awk '{print $1}')"
  else
    echo -e "  ${RED}[FAIL]${NC} $(echo $line | awk '{print $1}')"
  fi
done

echo ""
echo "Logging Stack:"
docker compose -f docker-compose.logging.yml ps 2>/dev/null | grep -E "elasticsearch|kibana|logstash|filebeat|jaeger" | while read line; do
  if echo "$line" | grep -q "Up"; then
    echo -e "  ${GREEN}[OK]${NC} $(echo $line | awk '{print $1}')"
  else
    echo -e "  ${RED}[FAIL]${NC} $(echo $line | awk '{print $1}')"
  fi
done

# 2. Elasticsearch
echo ""
echo "[2]  ELASTICSEARCH STATUS"
echo "─────────────────────────────────────────────────────────────"

ES_HEALTH=$(curl -s "http://localhost:9201/_cluster/health" 2>/dev/null)
if [ $? -eq 0 ]; then
  ES_STATUS=$(echo "$ES_HEALTH" | jq -r '.status')
  echo -e "  Status: ${GREEN}$ES_STATUS${NC}"
  echo "  Nodes: $(echo "$ES_HEALTH" | jq -r '.number_of_nodes')"
else
  echo -e "  ${RED}[FAIL] Elasticsearch not accessible${NC}"
  echo "  URL: http://localhost:9201"
fi

# 3. Dataset stats
echo ""
echo "[3]  DATASET STATISTICS"
echo "─────────────────────────────────────────────────────────────"

# Check if indices exist
INDICES=$(curl -s "http://localhost:9201/_cat/indices/openproject-car-*" 2>/dev/null | wc -l)
if [ "$INDICES" -gt 0 ]; then
  echo -e "  ${GREEN}[OK]${NC} Found $INDICES index/indices"
  
  # Total count
  TOTAL=$(curl -s "http://localhost:9201/openproject-car-*/_count" 2>/dev/null | jq -r '.count // 0')
  echo "  Total events: $TOTAL"
  
  if [ "$TOTAL" -gt 0 ]; then
    # Label distribution
    NORMAL=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:normal" 2>/dev/null | jq -r '.count // 0')
    MALICIOUS=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:malicious" 2>/dev/null | jq -r '.count // 0')
    UNLABELED=$((TOTAL - NORMAL - MALICIOUS))
    
    echo ""
    echo "  Label Distribution:"
    echo "    Normal:     $NORMAL ($(awk "BEGIN {printf \"%.1f\", ($NORMAL * 100.0 / $TOTAL)}")%)"
    echo "    Malicious:  $MALICIOUS ($(awk "BEGIN {printf \"%.1f\", ($MALICIOUS * 100.0 / $TOTAL)}")%)"
    echo "    Unlabeled:  $UNLABELED ($(awk "BEGIN {printf \"%.1f\", ($UNLABELED * 100.0 / $TOTAL)}")%)"
    
    # CAR normalization
    WITH_CAR=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=_exists_:car.object" 2>/dev/null | jq -r '.count // 0')
    echo ""
    echo "  CAR Normalization:"
    echo "    With CAR fields: $WITH_CAR ($(awk "BEGIN {printf \"%.1f\", ($WITH_CAR * 100.0 / $TOTAL)}")%)"
    
    # Attack techniques
    echo ""
    echo "  Attack Techniques:"
    T1078=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1078" 2>/dev/null | jq -r '.count // 0')
    T1083=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1083" 2>/dev/null | jq -r '.count // 0')
    T1071=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1071.001" 2>/dev/null | jq -r '.count // 0')
    T1498=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1498.002" 2>/dev/null | jq -r '.count // 0')
    
    echo "    T1078 (Credential Stuffing): $T1078"
    echo "    T1083 (API Reconnaissance):  $T1083"
    echo "    T1071 (C2 Beaconing):        $T1071"
    echo "    T1498 (Application DoS):     $T1498"
  else
    echo -e "  ${YELLOW}[WARN]${NC}  No data in indices yet"
  fi
else
  echo -e "  ${RED}[FAIL]${NC} No openproject-car-* indices found"
fi

# 4. Log sample
echo ""
echo "[4]  LOG QUALITY SAMPLE"
echo "─────────────────────────────────────────────────────────────"

SAMPLE=$(curl -s "http://localhost:9201/openproject-car-*/_search?size=1&pretty" 2>/dev/null)
if echo "$SAMPLE" | jq -e '.hits.hits[0]' > /dev/null 2>&1; then
  echo "  Latest log structure:"
  echo "$SAMPLE" | jq -r '.hits.hits[0]._source | {
    timestamp: .["@timestamp"],
    event_label: .event.label,
    experiment_id: .experiment.id,
    car_object: .car.object,
    car_action: .car.action,
    attack_technique: .attack.technique,
    source_ip: .car.src_ip
  }' 2>/dev/null | sed 's/^/    /'
else
  echo -e "  ${YELLOW}[WARN]${NC}  No sample log available"
fi

# 5. Gatling
echo ""
echo "[5]  GATLING SIMULATIONS STATUS"
echo "─────────────────────────────────────────────────────────────"

GATLING_DIR=~/Code/System_Security/tests/gatling-3.10.3
if [ -d "$GATLING_DIR" ]; then
  echo -e "  ${GREEN}[OK]${NC} Gatling installed at: $GATLING_DIR"
  
  SIMS=$(find ~/Code/System_Security/tests/gatling-3.10.3/user-files/simulations/openproject -name "*.scala" 2>/dev/null | wc -l)
  echo "  Simulations found: $SIMS"
  
  if [ "$SIMS" -gt 0 ]; then
    find ~/Code/System_Security/tests/gatling-3.10.3/user-files/simulations/openproject -name "*.scala" -exec basename {} \; | sed 's/^/    - /'
  fi
else
  echo -e "  ${RED}[FAIL]${NC} Gatling not installed"
fi

# 6. Endpoints
echo ""
echo "[6]  ACCESS POINTS"
echo "─────────────────────────────────────────────────────────────"

# Test each endpoint
endpoints=(
  "OpenProject|http://localhost:8080"
  "Kibana|http://localhost:5602"
  "Elasticsearch|http://localhost:9201"
  "Jaeger|http://localhost:16686"
)

for endpoint in "${endpoints[@]}"; do
  IFS='|' read -r name url <<< "$endpoint"
  if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q "200\|302"; then
    echo -e "  ${GREEN}[OK]${NC} $name: $url"
  else
    echo -e "  ${RED}[FAIL]${NC} $name: $url (not accessible)"
  fi
done

# 7. Completeness score
echo ""
echo "[7]  PROJECT COMPLETENESS"
echo "─────────────────────────────────────────────────────────────"

SCORE=0
MAX_SCORE=10

# Infrastructure (2 points)
if docker compose ps 2>/dev/null | grep -q "Up.*web"; then SCORE=$((SCORE+1)); fi
if docker compose -f docker-compose.logging.yml ps 2>/dev/null | grep -q "Up.*elasticsearch"; then SCORE=$((SCORE+1)); fi

# Dataset (3 points)
if [ "$TOTAL" -gt 1000 ]; then SCORE=$((SCORE+1)); fi
if [ "$MALICIOUS" -gt 100 ]; then SCORE=$((SCORE+1)); fi
if [ "$WITH_CAR" -gt 100 ]; then SCORE=$((SCORE+1)); fi

# Labeling (2 points)
if [ "$WITH_LABELS" -gt 100 ]; then SCORE=$((SCORE+1)); fi
if [ "$T1078" -gt 0 ] && [ "$T1083" -gt 0 ]; then SCORE=$((SCORE+1)); fi

# Simulations (2 points)
if [ "$SIMS" -ge 4 ]; then SCORE=$((SCORE+2)); fi

# Documentation (1 point)
if [ -f ~/Code/System_Security/README.md ]; then SCORE=$((SCORE+1)); fi

PERCENT=$((SCORE * 10))
echo "  Completion: $SCORE/$MAX_SCORE ($PERCENT%)"
echo ""

if [ "$SCORE" -ge 8 ]; then
  echo -e "  ${GREEN}[OK] Project is ready for submission!${NC}"
elif [ "$SCORE" -ge 5 ]; then
  echo -e "  ${YELLOW}[WARN] Project needs some work${NC}"
else
  echo -e "  ${RED}[FAIL] Project incomplete${NC}"
fi

# 8. Next steps
echo ""
echo "[8]  RECOMMENDED NEXT STEPS"
echo "─────────────────────────────────────────────────────────────"

if [ "$TOTAL" -eq 0 ]; then
  echo "  1. Run experiments to generate data:"
  echo "     cd ~/Code/System_Security/tests"
  echo "     ./run-all-experiments.sh"
elif [ "$MALICIOUS" -eq 0 ]; then
  echo "  1. Labels not working - check Filebeat config"
  echo "  2. Restart Filebeat after applying container labels"
elif [ "$WITH_CAR" -lt 100 ]; then
  echo "  1. CAR normalization incomplete"
  echo "  2. Check Logstash pipeline configuration"
else
  echo "  1. [OK] Dataset looks good!"
  echo "  2. Create detection rules in Kibana"
  echo "  3. Export dataset for documentation"
  echo "  4. Write final report"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Status check complete!"
echo "════════════════════════════════════════════════════════════"
