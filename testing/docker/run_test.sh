#!/bin/bash

# Mock metadata service calls
export MOCK_METADATA=1

# Override curl for metadata calls
curl() {
    if [[ "$*" == *"169.254.169.254/latest/meta-data/instance-id"* ]]; then
        cat /tmp/mock_metadata/instance-id
    elif [[ "$*" == *"169.254.169.254/latest/meta-data/placement/region"* ]]; then
        cat /tmp/mock_metadata/region
    elif [[ "$*" == *"169.254.169.254/latest/meta-data/public-ipv4"* ]]; then
        cat /tmp/mock_metadata/public-ipv4
    else
        /usr/bin/curl "$@"
    fi
}

# Override aws CLI for tagging (just echo what would be done)
aws() {
    if [[ "$1" == "ec2" && "$2" == "create-tags" ]]; then
        echo "Mock: Would create AWS tags: $*"
        return 0
    else
        /usr/bin/aws "$@" || echo "Note: AWS CLI call failed (expected in test environment)"
    fi
}

export -f curl aws

echo "🧪 Starting CNAPPuccino User Data Test"
echo "======================================="
echo ""

# Run the user data script with verbose output
echo "📋 Executing user data script with debugging..."
/bin/bash -x /usr/local/bin/test_user_data.sh 2>&1 | tee /tmp/logs/user_data_debug.log
exit_code=${PIPESTATUS[0]}

echo ""
echo "======================================="
if [ $exit_code -eq 0 ]; then
    echo "✅ User data script completed successfully!"
else
    echo "❌ User data script failed with exit code: $exit_code"
    echo ""
    echo "📋 Last 20 lines of output:"
    tail -20 /tmp/logs/user_data_debug.log
fi
echo "======================================="