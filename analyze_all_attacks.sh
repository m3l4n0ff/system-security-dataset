#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║          ATTACK PATTERN ANALYSIS - ALL TECHNIQUES        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

for technique in "T1078" "T1083" "T1071.001" "T1498.002"; do
  case "$technique" in
    "T1078") name="Credential Stuffing" ;;
    "T1083") name="API Reconnaissance" ;;
    "T1071.001") name="C2 Beaconing" ;;
    "T1498.002") name="Application DoS" ;;
  esac
  
  echo "════════════════════════════════════════════════════════════"
  echo " $technique - $name"
  echo "════════════════════════════════════════════════════════════"
  
  # Get sample traces
  curl -s "http://localhost:9201/openproject-car-*/_search?size=10" -H 'Content-Type: application/json' -d"{
    \"query\": {\"term\": {\"attack.technique\": \"$technique\"}},
    \"sort\": [{\"@timestamp\": \"asc\"}],
    \"_source\": [\"@timestamp\", \"trace.id\", \"http.request.path\", \"http.response.status_code\", \"car.action\"]
  }" | jq -r '.hits.hits[]._source | 
    "[\(.["@timestamp"] | split("T")[1] | split(".")[0])] " +
    "\(.trace.id[0:8]) " +
    "\(.http.request.path // .car.object // "system") " +
    "→ \(.http.response.status_code // .car.action // "---")"'
  
  echo ""
done

echo "════════════════════════════════════════════════════════════"
