#!/usr/bin/env bash
# Creates the login_monitoring_system database and the application user on a
# LOCAL MySQL server, using DB_USERNAME / DB_PASSWORD from the .env file.
# You will be asked for the MySQL root password (it is not stored anywhere).
#
# Usage:  ./scripts/setup-local-mysql.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "No .env file found. Run: cp .env.example .env  and edit it first." >&2
  exit 1
fi

# Read the two values we need from .env (simple KEY=VALUE lines)
DB_USERNAME=$(grep -E '^DB_USERNAME=' .env | head -1 | cut -d= -f2-)
DB_PASSWORD=$(grep -E '^DB_PASSWORD=' .env | head -1 | cut -d= -f2-)

if [[ -z "$DB_USERNAME" || -z "$DB_PASSWORD" ]]; then
  echo "DB_USERNAME and DB_PASSWORD must be set in .env" >&2
  exit 1
fi
if [[ "$DB_PASSWORD" == *"'"* ]]; then
  echo "DB_PASSWORD must not contain a single quote (') character." >&2
  exit 1
fi

echo "Creating database 'login_monitoring_system' and user '$DB_USERNAME'@'localhost'..."
echo "Enter your MySQL root password when asked."

mysql -u root -p <<SQL
CREATE DATABASE IF NOT EXISTS login_monitoring_system
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS login_monitoring_system_test
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USERNAME}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
ALTER USER '${DB_USERNAME}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON login_monitoring_system.* TO '${DB_USERNAME}'@'localhost';
GRANT ALL PRIVILEGES ON login_monitoring_system_test.* TO '${DB_USERNAME}'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "Done. Database and user are ready."
