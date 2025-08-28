# CNAPPuccino Testing

Local testing tools for debugging and validating the CNAPPuccino user data script.

## Quick Start

```bash
# Start the test environment
./test_user_data.sh

# Watch the script execution
./test_user_data.sh logs

# Get a shell in the container for debugging
./test_user_data.sh shell

# Clean up when done
./test_user_data.sh stop
```

## Directory Structure

```
testing/
├── README.md              # This file
├── test_user_data.sh       # Main test script
├── logs/                   # Test output logs
└── docker/                 # Docker configuration
    ├── Dockerfile          # Test environment image
    ├── docker-compose.yml  # Container orchestration
    └── run_test.sh         # Script that runs inside container
```

## What It Tests

- ✅ **Package Installation** - Verifies vulnerable packages install correctly
- ✅ **Service Configuration** - Tests Apache, Nginx, PHP, MySQL setup
- ✅ **Vulnerability Creation** - Confirms Shellshock, Heartbleed, etc. are present
- ✅ **CSPM Assets** - Validates hardcoded credentials and misconfigurations
- ✅ **Script Completion** - Ensures user data runs to completion without errors

## Requirements

- Docker and Docker Compose
- Sufficient disk space for Ubuntu 16.04 base image

## Usage from Root Directory

```bash
# All commands can be run from the project root:
testing/test_user_data.sh
testing/test_user_data.sh logs
testing/test_user_data.sh shell
testing/test_user_data.sh stop
```