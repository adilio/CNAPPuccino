# Docker test environment for CNAPPuccino user data script
FROM ubuntu:16.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies that would be available on a fresh EC2 instance
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    awscli \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create directories that would exist on EC2
RUN mkdir -p /var/log \
    && mkdir -p /opt \
    && mkdir -p /var/www/html \
    && mkdir -p /tmp/logs

# Copy the user data script and test runner into the container
COPY terraform/user_data.sh.gist /usr/local/bin/test_user_data.sh
COPY testing/docker/run_test.sh /usr/local/bin/run_test.sh
RUN chmod +x /usr/local/bin/test_user_data.sh /usr/local/bin/run_test.sh

# Create mock metadata files
RUN mkdir -p /tmp/mock_metadata && \
    echo "i-1234567890abcdef0" > /tmp/mock_metadata/instance-id && \
    echo "us-east-1" > /tmp/mock_metadata/region && \
    echo "10.0.0.100" > /tmp/mock_metadata/public-ipv4

# Set working directory
WORKDIR /root

# Default command runs our test script
CMD ["/usr/local/bin/run_test.sh"]