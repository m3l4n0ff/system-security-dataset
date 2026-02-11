#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           C2 BEACONING PATTERN ANALYSIS                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Get C2 beacon traces
curl -s "http://localhost:9201/openproject-car-*/_search?size=100" -H 'Content-Type: application/json' -d'{
  "query": {
    "bool": {
      "must": [
        {"term": {"attack.technique": "T1071.001"}},
        {"exists": {"field": "http.request.path"}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}],
  "_source": ["@timestamp", "trace.id", "http.request.path", "http.response.status_code"]
}' > /tmp/c2_traces.json

TOTAL=$(jq '.hits.total.value' /tmp/c2_traces.json)

if [ "$TOTAL" -eq 0 ]; then
  echo "[ERROR] No C2 beaconing traces found"
  exit 1
fi

echo "Found $TOTAL C2 beacon requests"
echo ""
echo "════════════════════════════════════════════════════════════"
echo "   BEACON TIMELINE (showing timing pattern)"
echo "════════════════════════════════════════════════════════════"
echo ""

# Process and display
last_time=""
jq -r '.hits.hits[]._source | 
  "\(.["@timestamp"])|\(.trace.id[0:8])|\(.http.request.path)|\(.http.response.status_code)"' \
  /tmp/c2_traces.json | while IFS='|' read timestamp trace_id path status; do
  
  # Extract time
  time=$(echo "$timestamp" | cut -d'T' -f2 | cut -d'.' -f1)
  
  # Calculate time difference
  if [ -n "$last_time" ]; then
    # Simple time diff (seconds)
    current_sec=$(date -d "$time" +%s 2>/dev/null || echo "0")
    last_sec=$(date -d "$last_time" +%s 2>/dev/null || echo "0")
    diff=$((current_sec - last_sec))
    delta="(+${diff}s)"
  else
    delta=""
  fi
  last_time="$time"
  
  # Determine beacon type with emoji
  case "$path" in
    *notifications*) beacon="Check Commands" ;;
    */projects*) beacon="Exfil Projects" ;;
    */users*) beacon="Exfil Users" ;;
    */work_packages/1*) beacon="Command Channel" ;;
    */work_packages*) beacon="Exfil Tasks" ;;
    */attachments*) beacon="Exfil Files" ;;
    */queries*) beacon="Check Queries" ;;
    */api/v3) beacon="Heartbeat" ;;
    *) beacon="$(basename $path)" ;;
  esac
  
  printf "[%s] %s %-30s → HTTP %s %s\n" "$time" "$trace_id" "$beacon" "$status" "$delta"
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo ""
echo "ANALYSIS:"
echo "  - Look for regular time intervals (e.g., +30s, +30s, +30s)"
echo "  - Automated attacks show consistent timing"
echo "  - Human users show random timing"
