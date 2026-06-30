#!/bin/bash
#
# HashNut MPC Installer
# Usage: double-click this script or run: bash install.sh
#

APP_NAME="HashNut MPC.app"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_SRC="${SCRIPT_DIR}/${APP_NAME}"
INSTALL_DIR="/Applications"

if [ ! -d "${APP_SRC}" ]; then
    echo "Error: ${APP_NAME} not found in ${SCRIPT_DIR}"
    echo "Please run this script from the DMG volume."
    read -p "Press Enter to exit..."
    exit 1
fi

echo "========================================="
echo "  HashNut MPC Installer"
echo "========================================="
echo ""

# Ask user: install to /Applications or run directly?
echo "Choose an option:"
echo "  1) Install to /Applications and launch"
echo "  2) Run directly without installing"
echo ""
read -p "Enter choice [1/2]: " choice

case "$choice" in
    1)
        echo ""
        echo "Installing to ${INSTALL_DIR}..."
        # Remove old version if exists
        if [ -d "${INSTALL_DIR}/${APP_NAME}" ]; then
            rm -rf "${INSTALL_DIR}/${APP_NAME}"
        fi
        cp -R "${APP_SRC}" "${INSTALL_DIR}/"
        xattr -cr "${INSTALL_DIR}/${APP_NAME}"
        echo "Installed successfully."
        echo "Launching ${APP_NAME}..."
        open "${INSTALL_DIR}/${APP_NAME}"
        ;;
    2)
        echo ""
        # Copy to tmp to avoid read-only DMG issues
        TMP_APP="/tmp/${APP_NAME}"
        rm -rf "${TMP_APP}"
        cp -R "${APP_SRC}" "${TMP_APP}"
        xattr -cr "${TMP_APP}"
        echo "Launching ${APP_NAME}..."
        open "${TMP_APP}"
        ;;
    *)
        echo "Invalid choice. Exiting."
        read -p "Press Enter to exit..."
        exit 1
        ;;
esac
