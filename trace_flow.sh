#!/bin/bash

TRACE_ID="$1"

if [ -z "$TRACE_ID" ]; then
  # Get a random malicious trace
  TRACE_ID=$(curl -s "http://localhost:9201/openproject-car-*/_search?size=1" -H 'Content-Type: application/json' -d'{
    "query": {"term": {"event.label": "malicious"}},
    "_source": ["trace.id"]
  }' | jq -r '.hits.hits[0]._source.trace.id')
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║              REQUEST FLOW VISUALIZATION                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Trace ID: $TRACE_ID"
echo ""

# Get all logs for this trace
curl -s "http://localhost:9201/openproject-car-*/_search?size=50" -H 'Content-Type: application/json' -d"{
  \"query\": {\"term\": {\"trace.id\": \"$TRACE_ID\"}},
  \"sort\": [{\"@timestamp\": \"asc\"}],
  \"_source\": [
    \"@timestamp\",
    \"container.name\",
    \"http.request.method\",
    \"http.request.path\",
    \"http.response.status_code\",
    \"http.response.duration_ms\",
    \"car.action\",
    \"car.object\",
    \"event.label\",
    \"attack.technique\"
  ]
}" > /tmp/trace_flow.json

HITS=$(jq '.hits.total.value' /tmp/trace_flow.json)

if [ "$HITS" -eq 0 ]; then
  echo "[ERROR] No logs found for trace: $TRACE_ID"
  exit 1
fi

echo "Found $HITS log entries for this request"
echo ""
echo "════════════════════════════════════════════════════════════"

# Visual flow
jq -r '.hits.hits[] | ._source' /tmp/trace_flow.json | while read -r line; do
  container=$(echo "$line" | jq -r '.container.name // "unknown"' | cut -d'-' -f2)
  timestamp=$(echo "$line" | jq -r '.["@timestamp"]' | cut -d'T' -f2 | cut -d'.' -f1)
  method=$(echo "$line" | jq -r '.http.request.method // ""')
  path=$(echo "$line" | jq -r '.http.request.path // .car.object // ""')
  status=$(echo "$line" | jq -r '.http.response.status_code // ""')
  duration=$(echo "$line" | jq -r '.http.response.duration_ms // ""')
  label=$(echo "$line" | jq -r '.event.label[0] // ""')
  technique=$(echo "$line" | jq -r '.attack.technique // ""')
  
  # Indent based on container
  case "$container" in
    proxy) indent="" ;;
    web) indent="  │  " ;;
    *) indent="    │  " ;;
  esac
  
  # Build output
  output="${indent}[$timestamp] [$container]"
  
  if [ -n "$method" ]; then
    output="$output $method $path"
  else
    output="$output $path"
  fi
  
  if [ -n "$status" ]; then
    output="$output → HTTP $status"
  fi
  
  if [ -n "$duration" ]; then
    output="$output (${duration}ms)"
  fi
  
  if [ -n "$label" ]; then
    output="$output [$label]"
  fi
  
  if [ -n "$technique" ]; then
    output="$output {$technique}"
  fi
  
  echo "$output"
done

echo "════════════════════════════════════════════════════════════"
echo ""
echo "Legend:"
echo "  [proxy]     = Caddy reverse proxy (entry point)"
echo "  [web]       = Rails application"
echo "  [normal]    = Legitimate traffic"
echo "  [malicious] = Attack traffic"
echo "  {T1071}     = MITRE ATT&CK technique"
