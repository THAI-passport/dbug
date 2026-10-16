#!/system/bin/sh
# apply_stealth_props.sh: Masks Android system properties to present an un-debugged production state.
# Run via root on physical device: adb shell su -c "sh /data/local/tmp/apply_stealth_props.sh [apply|restore]"

ACTION="${1:-apply}"

if [ "$ACTION" = "restore" ]; then
    echo "[*] Restoring standard developer debug properties..."
    resetprop ro.debuggable 1
    resetprop sys.usb.state adb
    resetprop sys.usb.config adb
    resetprop init.svc.adbd running
    echo "[+] Restore complete."
    exit 0
fi

echo "[*] Applying stealth properties via resetprop..."

# 1. Mask userdebug / eng build indicators
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop ro.build.type user
resetprop ro.build.tags release-keys

# 2. Mask active USB debugging status to user-space apps
resetprop sys.usb.state mtp
resetprop sys.usb.config mtp
resetprop persist.sys.usb.config mtp

# 3. Mask adbd service state without terminating the underlying socket
resetprop init.svc.adbd stopped

echo "[+] Stealth properties applied. Device reports production state to unprivileged apps."
