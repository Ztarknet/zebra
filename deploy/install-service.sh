#!/bin/bash
set -e

echo "Installing zebrad systemd service..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please run as regular user (will use sudo when needed)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SERVICE_FILE="$SCRIPT_DIR/zebrad.service"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: zebrad.service file not found in $SCRIPT_DIR"
    exit 1
fi

# Get current user and paths
CURRENT_USER=$(whoami)
HOME_DIR="$HOME"
ZEBRA_DIR="$(dirname "$SCRIPT_DIR")"  # Parent directory of deploy folder

echo "Configuration:"
echo "  User: $CURRENT_USER"
echo "  Home: $HOME_DIR"
echo "  Zebra directory: $ZEBRA_DIR"
echo ""

# Create a temporary service file with correct paths
TMP_SERVICE=$(mktemp)
sed -e "s|{{USER}}|$CURRENT_USER|g" \
    -e "s|{{ZEBRA_DIR}}|$ZEBRA_DIR|g" \
    -e "s|{{HOME}}|$HOME_DIR|g" \
    "$SERVICE_FILE" > "$TMP_SERVICE"

# Copy the service file to systemd directory
echo "Installing service file..."
sudo cp "$TMP_SERVICE" /etc/systemd/system/zebrad.service
rm "$TMP_SERVICE"

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service
echo "Enabling zebrad service..."
sudo systemctl enable zebrad

echo ""
echo "Installation complete!"
echo ""
echo "Available commands:"
echo "  sudo systemctl start zebrad    # Start the service"
echo "  sudo systemctl stop zebrad     # Stop the service"
echo "  sudo systemctl restart zebrad  # Restart the service"
echo "  sudo systemctl status zebrad   # Check service status"
echo "  journalctl -u zebrad -f        # Follow service logs"
echo ""

