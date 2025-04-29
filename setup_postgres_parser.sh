#!/bin/bash

# Set database credentials from environment variables with fallbacks
DB_HOST="${DB_HOST:-localhost}"  # Use environment variable or fallback to default
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-root}"
DB_NAME="${DB_NAME:-securitytoolparser}"
DB_PORT="${DB_PORT:-5555}"

# Print current configuration (for debugging)
echo "Database Configuration:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo "  Password: [MASKED]"


# Step 1: Run PostgreSQL container with Docker
echo "Starting PostgreSQL container..."
# Check if PostgreSQL container is already running
if docker ps | grep -q "postgres-container"; then
  echo "PostgreSQL container is already running. Skipping container creation."
  echo "Parser is already setup!"
  echo "To run the parser, use: python3 run_parser.py -t <test> -p <test_output_file>"
else
    pip install -r requirements.txt
    docker run --name postgres-container \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    -e POSTGRES_DB="$DB_NAME" \
    -p "$DB_PORT":5432 \
    -d postgres
    
    # Wait for PostgreSQL to start
    echo "Waiting for PostgreSQL to start..."
    sleep 10
    
    # Step 2: Copy SQL file to container and execute it
    echo "Creating database tables..."
    docker cp securitytoolparser.sql postgres-container:/tmp/securitytoolparser.sql
    docker exec -i postgres-container psql -U "$DB_USER" -d "$DB_NAME" -f /tmp/securitytoolparser.sql
    
    # Step 6: Run the parser script if available
    if [ -f "insert_excel.py" ]; then
        echo "Running insert_excel.py..."
        python3 insert_excel.py
    fi
    
    # Check if we have necessary parameters for run_parser.py
    if [ $# -eq 4 ] && [ "$1" == "-t" ] && [ "$3" == "-p" ]; then
        TEST_TYPE=$2
        TEST_OUTPUT_FILE=$4
        
        echo "Running parser with test type: $TEST_TYPE and output file: $TEST_OUTPUT_FILE"
        python3 run_parser.py -t "$TEST_TYPE" -p "$TEST_OUTPUT_FILE"
    else
        echo "Parser setup complete!"
        echo "To run the parser, use: python3 run_parser.py -t <test> -p <test_output_file>"
    fi
fi