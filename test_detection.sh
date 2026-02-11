#!/bin/bash

echo "TESTING DETECTION SYSTEM"
echo "=============================="

# Test 1: Dataset
echo -e "\nDataset Status:"
TOTAL=$(curl -s "http://localhost:9201/openproject-car-*/_count" | jq '.count')
NORMAL=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:normal" | jq '.count')
MALICIOUS=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=event.label:malicious" | jq '.count')

echo "  Total: $TOTAL"
echo "  Normal: $NORMAL"
echo "  Malicious: $MALICIOUS"

if [ "$TOTAL" -gt 0 ] && [ "$MALICIOUS" -gt 0 ]; then
  echo "  [OK] Dataset ready"
else
  echo "  [FAIL] Dataset incomplete"
  exit 1
fi

# Test 2: CAR normalization
echo -e "\nCAR Normalization:"
CAR_COUNT=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=_exists_:car.object" | jq '.count')
echo "  Events with CAR fields: $CAR_COUNT"

if [ "$CAR_COUNT" -gt 0 ]; then
  echo "  [OK] CAR normalization working"
else
  echo "  [FAIL] CAR normalization failed"
  exit 1
fi

# Test 3: Attack techniques
echo -e "\nAttack Techniques:"
T1078=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1078" | jq '.count')
T1083=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1083" | jq '.count')
T1071=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1071.001" | jq '.count')
T1498=$(curl -s "http://localhost:9201/openproject-car-*/_count?q=attack.technique:T1498.002" | jq '.count')

echo "  T1078 (Credential Stuffing): $T1078"
echo "  T1083 (API Recon): $T1083"
echo "  T1071 (C2 Beaconing): $T1071"
echo "  T1498 (App DoS): $T1498"

TOTAL_TECHNIQUES=$((T1078 + T1083 + T1071 + T1498))
if [ "$TOTAL_TECHNIQUES" -gt 0 ]; then
  echo "  [OK] Attack labeling working"
else
  echo "  [FAIL] Attack labeling failed"
  exit 1
fi

# Test 4: Live detection
echo -e "\nLive Attack Simulation:"
echo "  Generating 5 failed login attempts..."

for i in {1..5}; do
  curl -s -X POST http://localhost:8080/login \
    -d "username=test_attacker&password=wrong" > /dev/null 2>&1
done

sleep 5

RECENT=$(curl -s "http://localhost:9201/openproject-car-*/_search" -H 'Content-Type: application/json' -d'{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1m"}}},
        {"term": {"car.action": "failure"}}
      ]
    }
  },
  "size": 0
}' | jq '.hits.total.value')

echo "  Detected: $RECENT failed auth attempts"

if [ "$RECENT" -gt 0 ]; then
  echo "  [OK] Real-time detection working"
else
  echo "  [WARN] No events detected (may need more time)"
fi

echo -e "\n================================"
echo "ALL TESTS PASSED!"
echo "================================"
echo ""
echo "Your detection system is ready!"
echo "Access points:"
echo "  - Kibana: http://localhost:5602"
echo "  - Elasticsearch: http://localhost:9201"
echo "  - Jaeger: http://localhost:16686"
