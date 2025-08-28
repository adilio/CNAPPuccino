#!/bin/bash
set -e

echo "🧪 CNAPPuccino User Data Script Tester"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

log "Building test environment..."
(cd "$DOCKER_DIR" && docker-compose build)

log "Starting test container..."
(cd "$DOCKER_DIR" && docker-compose up -d)

log "Waiting for container to start..."
sleep 3

echo ""
echo -e "${YELLOW}📋 Test Environment Ready!${NC}"
echo ""
echo "Available commands:"
echo "  testing/test_user_data.sh logs    - Watch the user data script output in real time"  
echo "  testing/test_user_data.sh shell   - Get a shell inside the test container"
echo "  testing/test_user_data.sh restart - Restart the test and run user data again"
echo "  testing/test_user_data.sh stop    - Stop and clean up the test environment"
echo "  testing/test_user_data.sh status  - Check container status and show recent logs"
echo ""

case "${1:-}" in
    "logs")
        echo -e "${BLUE}📋 Watching user data script output...${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop watching (container keeps running)${NC}"
        echo ""
        (cd "$DOCKER_DIR" && docker-compose logs -f cnappuccino-test)
        ;;
    "shell")
        echo -e "${BLUE}🐚 Opening shell in test container...${NC}"
        docker exec -it cnappuccino-debug /bin/bash
        ;;
    "restart")
        log "Restarting test environment..."
        (cd "$DOCKER_DIR" && docker-compose down && docker-compose up -d)
        sleep 2
        echo -e "${GREEN}✅ Test restarted. Use 'testing/test_user_data.sh logs' to watch output.${NC}"
        ;;
    "stop")
        log "Stopping test environment..."
        (cd "$DOCKER_DIR" && docker-compose down)
        echo -e "${GREEN}✅ Test environment stopped and cleaned up.${NC}"
        ;;
    "status")
        echo -e "${BLUE}📊 Container Status:${NC}"
        (cd "$DOCKER_DIR" && docker-compose ps)
        echo ""
        echo -e "${BLUE}📋 Recent logs (last 20 lines):${NC}"
        (cd "$DOCKER_DIR" && docker-compose logs --tail=20 cnappuccino-test)
        ;;
    *)
        echo -e "${GREEN}✅ Test environment is running!${NC}"
        echo ""
        echo "Next steps:"
        echo "1. Run: ${YELLOW}testing/test_user_data.sh logs${NC} to watch the user data script execution"
        echo "2. Run: ${YELLOW}testing/test_user_data.sh shell${NC} to debug inside the container" 
        echo "3. Run: ${YELLOW}testing/test_user_data.sh stop${NC} when done"
        ;;
esac