#!/bin/bash
# Define Grafana credentials
# Use environment variables (with defaults as fallback)
GRAFANA_USER="${GRAFANA_USER}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD}"
domain="${domain}"
GRAFANA_PORT="3100"

echo "GRAFANA_USER: $GRAFANA_USER"
echo "GRAFANA_PASSWORD: $GRAFANA_PASSWORD"
echo "domain: $domain"
echo "GRAFANA_PORT: $GRAFANA_PORT"

# Check if Grafana container is already running
if docker ps | grep -q grafana-container; then
  echo "Grafana container is already running, skipping installation"
else
  echo "Setting up Grafana container..."
  # Pull Grafana image
  docker pull grafana/grafana:latest

  # Create Docker volume for Grafana data
  docker volume create grafana-storage

  # Run Grafana container
  docker run -d \
    --name grafana-container \
    -p ${GRAFANA_PORT}:3000 \
    -e "GF_SECURITY_ADMIN_USER=${GRAFANA_USER}" \
    -e "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}" \
    -e "GF_INSTALL_PLUGINS=grafana-piechart-panel,grafana-worldmap-panel" \
    -v grafana-storage:/var/lib/grafana \
    -v /home/ubuntu/securelineparser/grafana/grafana.ini:/etc/grafana/grafana.ini \
    grafana/grafana:latest

  # Wait for Grafana to start
  echo "Waiting for Grafana to start..."
  sleep 30
fi

# Get existing service accounts or create a new one
SERVICE_ACCOUNTS=$(curl -s -X GET \
  -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
  "http://${domain}:${GRAFANA_PORT}/api/serviceaccounts/search")

# Check if service account already exists
SERVICE_ACCOUNT_ID=$(echo $SERVICE_ACCOUNTS | grep -o '"id":[0-9]*,"name":"secureline-service-account"' | grep -o '"id":[0-9]*' | cut -d ":" -f2)    

if [ -z "$SERVICE_ACCOUNT_ID" ]; then
  echo "Creating new service account..."
  # Create service account
  SERVICE_ACCOUNT_RESPONSE=$(curl -s -X POST \
    -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "secureline-service-account",
      "role": "Admin"
    }' \
    "http://${domain}:${GRAFANA_PORT}/api/serviceaccounts")

  SERVICE_ACCOUNT_ID=$(echo $SERVICE_ACCOUNT_RESPONSE | grep -o '"id":[0-9]*' | cut -d ":" -f2)

  if [ -z "$SERVICE_ACCOUNT_ID" ] || [ "$SERVICE_ACCOUNT_ID" == "null" ]; then
    echo "Failed to create service account. Response: $SERVICE_ACCOUNT_RESPONSE"
    exit 1
  fi

  echo "Service account created with ID: ${SERVICE_ACCOUNT_ID}"
else
  echo "Service account already exists with ID: ${SERVICE_ACCOUNT_ID}"
fi

# Get existing tokens for this service account
TOKENS=$(curl -s -X GET \
  -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
  "http://${domain}:${GRAFANA_PORT}/api/serviceaccounts/${SERVICE_ACCOUNT_ID}/tokens")

# Check if we need to create a new token
if echo "$TOKENS" | grep -q "secureline-token"; then
  echo "Token already exists, revoking and creating new token..."
  # Find the token ID to revoke it
  TOKEN_ID=$(echo $TOKENS | grep -o '"id":[0-9]*,"name":"secureline-token"' | grep -o '"id":[0-9]*' | cut -d ":" -f2)

  if [ ! -z "$TOKEN_ID" ]; then
    # Revoke the token
    curl -s -X POST \
      -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
      "http://${domain}:${GRAFANA_PORT}/api/serviceaccounts/${SERVICE_ACCOUNT_ID}/tokens/${TOKEN_ID}/revoke"
    echo "Previous token revoked"
  fi
fi

# Create a new token
TOKEN_RESPONSE=$(curl -s -X POST \
  -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "secureline-token",
    "secondsToLive": 0
  }' \
  "http://${domain}:${GRAFANA_PORT}/api/serviceaccounts/${SERVICE_ACCOUNT_ID}/tokens")

GRAFANA_API_KEY=$(echo $TOKEN_RESPONSE | grep -o '"key":"[^"]*' | cut -d "\"" -f4)

if [ -z "$GRAFANA_API_KEY" ] || [ "$GRAFANA_API_KEY" == "null" ]; then
  echo "Failed to create Grafana API key. Response: $TOKEN_RESPONSE"
  exit 1
fi

echo "Grafana API key created successfully"

# Add PostgreSQL data source if it doesn't exist
DATASOURCES=$(curl -s -X GET \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  "http://${domain}:${GRAFANA_PORT}/api/datasources")

if ! echo "$DATASOURCES" | grep -q "PostgreSQL"; then
    echo "Adding PostgreSQL data source..."

    # Create JSON payload with properly expanded variables
    JSON_PAYLOAD=$(cat <<EOF
{
    "name": "PostgreSQL",
    "type": "postgres",
    "url": "${domain}:5555",
    "access": "proxy",
    "user": "postgres",
    "database": "securitytoolparser",
    "basicAuth": false,
    "isDefault": true,
    "jsonData": {
        "sslmode": "disable",
        "postgresVersion": 1200
    },
    "secureJsonData": {
        "password": "postgres"
    }
}
EOF
    )

    # Send the request with the expanded JSON payload
    DATASOURCE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
        -d "$JSON_PAYLOAD" \
        "http://${domain}:${GRAFANA_PORT}/api/datasources")

    echo "PostgreSQL data source added to Grafana: $DATASOURCE_RESPONSE"
else
    echo "PostgreSQL data source already exists."
fi

# Find and import all dashboard JSON files from the repository
cd /home/ubuntu/securelineparser
DASHBOARD_PATH="/home/ubuntu/securelineparser/dashboards"

# Make sure jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is required but not installed. Installing..."
    sudo apt-get update && sudo apt-get install -y jq
fi

# Find all JSON dashboard files and import them
for dashboard_file in $(find ${DASHBOARD_PATH} -name "*.json"); do
  echo "Importing dashboard: ${dashboard_file}"

  # Check if file exists and is readable
  if [ ! -r "$dashboard_file" ]; then
    echo "Error: Cannot read dashboard file: $dashboard_file"
    continue
  fi

  # Read the dashboard JSON content
  DASHBOARD_JSON=$(cat "${dashboard_file}")

  # Check if JSON is valid
  if ! echo "$DASHBOARD_JSON" | jq empty &>/dev/null; then
    echo "Error: Invalid JSON in $dashboard_file"
    continue
  fi

  # Prepare the dashboard JSON for import
  # Make sure it has an ID set to null (so it doesn't conflict)
  # and any dashboard reference IDs are also properly set
  PROCESSED_JSON=$(echo "$DASHBOARD_JSON" | jq '.id = null | .uid = null | del(.version)')

  # Prepare the import payload
  IMPORT_PAYLOAD=$(jq -n \
    --argjson dashboard "$PROCESSED_JSON" \
    '{
      "dashboard": $dashboard,
      "overwrite": true,
      "message": "Imported via script",
      "folderId": 0
    }')

  # Import dashboard with properly formatted JSON
  RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
    -d "$IMPORT_PAYLOAD" \
    "http://${domain}:${GRAFANA_PORT}/api/dashboards/db")

  # Check the response
  if echo "$RESPONSE" | grep -q '"id"'; then
    DASHBOARD_UID=$(echo "$RESPONSE" | jq -r '.uid // "unknown"')
    echo "Dashboard imported successfully with UID: $DASHBOARD_UID"
  else
    echo "Dashboard import failed:"
    echo "$RESPONSE" | jq '.'
  fi
done

echo "Grafana setup completed successfully"
echo "Grafana is accessible at: http://${domain}:${GRAFANA_PORT}"
echo "Username: ${GRAFANA_USER}"
echo "Password: ${GRAFANA_PASSWORD}"