#!/usr/bin/env bash
# install-service.sh
# Installs the datasec breach monitor as a background service.
# Linux: systemd user service
# macOS: launchd user agent

set -e

OS="$(uname -s)"

if [ "$OS" = "Linux" ]; then
    echo "Installing systemd user service..."
    mkdir -p "$HOME/.config/systemd/user"
    cp services/datasec-monitor.service "$HOME/.config/systemd/user/datasec-monitor.service"

    # Replace %h with actual home path (some systemd versions need it explicit)
    sed -i "s|%h|$HOME|g" "$HOME/.config/systemd/user/datasec-monitor.service"

    systemctl --user daemon-reload
    systemctl --user enable datasec-monitor.service
    systemctl --user start  datasec-monitor.service
    systemctl --user status datasec-monitor.service --no-pager

    echo ""
    echo "Service installed. Check logs with:"
    echo "  journalctl --user -u datasec-monitor -f"

elif [ "$OS" = "Darwin" ]; then
    echo "Installing launchd user agent..."
    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"

    # Replace placeholder path with actual datasec binary location
    DATASEC_BIN="$(which datasec 2>/dev/null || echo "$HOME/.local/bin/datasec")"
    sed "s|/usr/local/bin/datasec|$DATASEC_BIN|g" \
        services/com.datasec.monitor.plist \
        > "$PLIST_DIR/com.datasec.monitor.plist"

    launchctl load "$PLIST_DIR/com.datasec.monitor.plist"
    launchctl start com.datasec.monitor

    echo ""
    echo "Service installed. Check logs with:"
    echo "  tail -f /tmp/datasec-monitor.log"

else
    echo "Unsupported OS: $OS"
    echo "For Windows, use the bundled PowerShell helper instead:"
    echo "  powershell -ExecutionPolicy Bypass -File services/install-task.ps1"
    exit 1
fi

echo ""
echo "To uninstall:"
if [ "$OS" = "Linux" ]; then
    echo "  systemctl --user disable --now datasec-monitor.service"
    echo "  rm ~/.config/systemd/user/datasec-monitor.service"
else
    echo "  launchctl unload ~/Library/LaunchAgents/com.datasec.monitor.plist"
    echo "  rm ~/Library/LaunchAgents/com.datasec.monitor.plist"
fi
