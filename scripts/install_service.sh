#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' 

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IOTRC_PATH="$PROJECT_ROOT/iotrc.py"
SERVICE_NAME="iotracer"
SYSTEM_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_OUTPUT="/var/log/iotracer/traces"

function install_service() {
    echo -e "${YELLOW}installing IO-Tracer systemd system service...${NC}"
    
    if [ ! -f "$IOTRC_PATH" ]; then
        echo -e "${RED}ERROR: iotrc.py not found at $IOTRC_PATH${NC}"
        exit 1
    fi
    
    sudo mkdir -p "$DEFAULT_OUTPUT"
    sudo chown $USER:$USER "$DEFAULT_OUTPUT"
    
    sudo bash -c "cat > $SYSTEM_SERVICE_FILE" << EOF
[Unit]
Description=IO Tracer System Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_ROOT
ExecStart=/usr/bin/python3 $IOTRC_PATH --output $DEFAULT_OUTPUT
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    echo -e "${GREEN}service file created at: $SYSTEM_SERVICE_FILE${NC}"
    
    sudo systemctl daemon-reload
    
    sudo systemctl enable "$SERVICE_NAME.service"
    
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}IO-Tracer Service Installed Successfully!${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "project root:     $PROJECT_ROOT"
    echo "IOTracer script:  $IOTRC_PATH"
    echo "service name:     $SERVICE_NAME"
    echo "service file:     $SYSTEM_SERVICE_FILE"
    echo "output directory: $DEFAULT_OUTPUT"
    echo ""
    echo "Commands:"
    echo "  start now:      sudo systemctl start $SERVICE_NAME"
    echo "  stop:           sudo systemctl stop $SERVICE_NAME"
    echo "  status:         sudo systemctl status $SERVICE_NAME"
    echo "  siew logs:      sudo journalctl -u $SERVICE_NAME -f"
    echo "  disable:        sudo systemctl disable $SERVICE_NAME"
    echo ""
}

function uninstall_service() {
    echo -e "${YELLOW}uninstalling IO-Tracer service...${NC}"
    
    sudo systemctl stop "$SERVICE_NAME.service" 2>/dev/null
    sudo systemctl disable "$SERVICE_NAME.service" 2>/dev/null
    
    if [ -f "$SYSTEM_SERVICE_FILE" ]; then
        sudo rm "$SYSTEM_SERVICE_FILE"
        echo -e "${GREEN}service file removed: $SYSTEM_SERVICE_FILE${NC}"
    else
        echo -e "${YELLOW}service file not found: $SYSTEM_SERVICE_FILE${NC}"
    fi
    
    sudo systemctl daemon-reload
    
    echo -e "${GREEN}service uninstalled successfully${NC}"
}

function show_status() {
    echo "============================================================"
    echo "IO-Tracer service status"
    echo "============================================================"
    
    if [ -f "$SYSTEM_SERVICE_FILE" ]; then
        echo "service file:     INSTALLED"
        echo "location:         $SYSTEM_SERVICE_FILE"
        echo "project root:     $PROJECT_ROOT"
        echo "IOTracer script:  $IOTRC_PATH"
        echo ""
        sudo systemctl status "$SERVICE_NAME.service" --no-pager
    else
        echo "service file:     NOT INSTALLED"
        echo "expected at:      $SYSTEM_SERVICE_FILE"
    fi
    
    echo "============================================================"
}

case "${1:-}" in
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    status)
        show_status
        ;;
    start)
        sudo systemctl start "$SERVICE_NAME.service"
        echo "service started. Check status with: sudo systemctl status $SERVICE_NAME"
        ;;
    stop)
        sudo systemctl stop "$SERVICE_NAME.service"
        echo "service stopped."
        ;;
    restart)
        sudo systemctl restart "$SERVICE_NAME.service"
        echo "service restarted."
        ;;
    logs)
        sudo journalctl -u "$SERVICE_NAME.service" -f
        ;;
    *)
        echo "Usage: $0 {install|uninstall|status|start|stop|restart|logs}"
        echo ""
        echo "Options:"
        echo "  install      Install and enable the service"
        echo "  uninstall    Stop and remove the service"
        echo "  status       Show service status"
        echo "  start        Start the service now"
        echo "  stop         Stop the service"
        echo "  restart      Restart the service"
        echo "  logs         View live service logs"
        exit 1
        ;;
esac
