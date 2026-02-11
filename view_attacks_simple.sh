#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║              ATTACK TRAFFIC ANALYSIS                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

for technique in "T1078" "T1083" "T1071.001" "T1498.002"; do
  case "$technique" in
    "T1078") name="Credential Stuffing" ;;
    "T1083") name="API Reconnaissance" ;;
    "T1071.001") name="C2 Beaconing" ;;
    "T1498.002") name="Application DoS" ;;
  esac
  
  count=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:$technique" | jq '.count')
  
  echo "════════════════════════════════════════════════════════════"
  echo " $name ($technique)"
  echo " Events: $count"
  echo "════════════════════════════════════════════════════════════"
  
  if [ "$count" -gt 0 ]; then
    # Get actual log samples
    curl -s "http://localhost:9201/openproject-car-*/_search?size=5" -H 'Content-Type: application/json' -d"{
      \"query\": {\"term\": {\"attack.technique\": \"$technique\"}},
      \"sort\": [{\"@timestamp\": \"asc\"}]
    }" | jq -r '.hits.hits[]._source | 
      "  [\(.["@timestamp"] | split("T")[1] | split(".")[0])] " +
      (if .container.name then .container.name else "unknown" end) + " | " +
      (if .caddy.request.uri then .caddy.request.uri 
       elif .http.request.path then .http.request.path
       elif .car.object then .car.object
       else "system event" end) + " | " +
      (if .caddy.status then ("HTTP " + (.caddy.status | tostring))
       elif .http.response.status_code then ("HTTP " + (.http.response.status_code | tostring))
       elif .car.action then .car.action
       else "---" end)'
  fi
  
  echo ""
done

echo "════════════════════════════════════════════════════════════"
