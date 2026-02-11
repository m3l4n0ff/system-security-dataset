#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         OPENPROJECT TRACE VIEWER (via Elasticsearch)    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Get a random trace ID from attack traffic
echo "Finding attack traces..."
TRACE_ID=$(curl -s "http://localhost:9201/openproject-car-*/_search?size=1" -H 'Content-Type: application/json' -d'{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.label": "malicious"}},
        {"exists": {"field": "trace.id"}}
      ]
    }
  },
  "_source": ["trace.id"]
}' | jq -r '.hits.hits[0]._source.trace.id')

if [ -z "$TRACE_ID" ] || [ "$TRACE_ID" == "null" ]; then
  echo "[ERROR] No attack traces with trace.id found"
  exit 1
fi

echo "Selected Trace: $TRACE_ID"
echo ""

# Get all logs for this trace
echo "════════════════════════════════════════════════════════════"
echo "   TRACE TIMELINE: $TRACE_ID"
echo "════════════════════════════════════════════════════════════"
echo ""

curl -s "http://localhost:9201/openproject-car-*/_search?size=50&pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {\"term\": {\"trace.id\": \"$TRACE_ID\"}},
  \"sort\": [{\"@timestamp\": \"asc\"}],
  \"_source\": [
    \"@timestamp\",
    \"container.name\",
    \"http.request.method\",
    \"http.request.path\",
    \"http.response.status_code\",
    \"http.response.duration_ms\",
    \"event.label\",
    \"attack.technique\",
    \"car.action\"
  ]
}" | jq -r '.hits.hits[] | .._source | 
  "[\(._source["@timestamp"] | split("T")[1] | split(".")[0])] " +
  "[\(.container.name | split("-")[1])] " +
  "\(.http.request.method // "---") " +
  "\(.http.request.path // .car.object // "system") " +
  "→ HTTP \(.http.response.status_code // "---") " +
  "(\(.http.response.duration_ms // 0)ms) " +
  if .event.label then "[\(.event.label | join(","))]" else "" end +
  if .attack.technique then " T:\(.attack.technique)" else "" end'

echo ""
echo "════════════════════════════════════════════════════════════"
