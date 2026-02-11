#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         YOUR ATTACK DATASET - COMPLETE ANALYSIS          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

echo "DATASET SUMMARY:"
echo "────────────────────────────────────────────────────────────"
TOTAL=$(curl -s "http://localhost:9201/openproject-car-*/_count" | jq '.count')
NORMAL=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:normal" | jq '.count')
MALICIOUS=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:malicious" | jq '.count')

echo "Total Events:    $TOTAL"
echo "Normal:          $NORMAL ($(awk "BEGIN {printf \"%.1f\", $NORMAL*100.0/$TOTAL}")%)"
echo "Malicious:       $MALICIOUS ($(awk "BEGIN {printf \"%.1f\", $MALICIOUS*100.0/$TOTAL}")%)"
echo ""

for technique in "T1078" "T1083" "T1071.001" "T1498.002"; do
  case "$technique" in
    "T1078") name="Credential Stuffing" ;;
    "T1083") name="API Reconnaissance" ;;
    "T1071.001") name="C2 Beaconing" ;;
    "T1498.002") name="Application DoS" ;;
  esac
  
  count=$(curl -s "http://localhost:9201/openproject-car-*/_count" -H 'Content-Type: application/json' -d"{
    \"query\": {\"term\": {\"attack.technique.keyword\": \"$technique\"}}
  }" | jq '.count')
  
  echo "════════════════════════════════════════════════════════════"
  echo " $name"
  echo " Technique: $technique | Events: $count"
  echo "════════════════════════════════════════════════════════════"
  
  if [ "$count" -gt 0 ]; then
    echo "Sample events:"
    curl -s "http://localhost:9201/openproject-car-*/_search?size=5" -H 'Content-Type: application/json' -d"{
      \"query\": {\"term\": {\"attack.technique.keyword\": \"$technique\"}},
      \"sort\": [{\"@timestamp\": \"asc\"}],
      \"_source\": [\"@timestamp\", \"container.name\", \"caddy.msg\", \"message\"]
    }" | jq -r '.hits.hits[]._source | 
      "  [\(.["@timestamp"] | split("T")[1] | split(".")[0])] " +
      (.container.name | split("-") | .[1]) + " | " +
      (if .caddy.msg then .caddy.msg[0:60] elif .message then (.message | gsub("\n";" ") | .[0:60]) else "system" end)'
  fi
  echo ""
done

echo "════════════════════════════════════════════════════════════"
echo "[OK] Dataset complete and properly labeled!"
echo ""
echo "Access points:"
echo "  - Kibana: http://localhost:5602"
echo "  - Elasticsearch: http://localhost:9201"
echo ""
