#!/bin/bash
set -e

echo "Uninstalling zebrad systemd service..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please run as regular user (will use sudo when needed)"
    exit 1
fi

# Stop the service if it's running
if systemctl is-active --quiet zebrad; then
    echo "Stopping zebrad service..."
    sudo systemctl stop zebrad
fi

# Disable the service
if systemctl is-enabled --quiet zebrad 2>/dev/null; then
    echo "Disabling zebrad service..."
    sudo systemctl disable zebrad
fi

# Remove the service file
if [ -f /etc/systemd/system/zebrad.service ]; then
    echo "Removing service file..."
    sudo rm /etc/systemd/system/zebrad.service
fi

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo ""
echo "Uninstallation complete!"
echo ""

