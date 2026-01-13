#!/usr/bin/env bash
set -euo pipefail

BOOT_MOUNT="/media/leo/boot"
GRUB_CFG="$BOOT_MOUNT/grub2/grub.cfg"
BLS_DIR="$BOOT_MOUNT/loader/entries"

echo "🔧 Patching GRUB in $BOOT_MOUNT"

# 1. Patch grub.cfg with serial terminal settings
if [ -f "$GRUB_CFG" ]; then
    echo "📄 Patching $GRUB_CFG..."
    cp "$GRUB_CFG" "${GRUB_CFG}.bak"
    
    if ! grep -q "serial --unit=0" "$GRUB_CFG"; then
        # Insert at the top (after header comments usually safe, or just prepend)
        # Using temp file to allow verifying content
        cat > /tmp/grub_serial_header.txt <<EOF
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console
EOF
        cat /tmp/grub_serial_header.txt "$GRUB_CFG" > "${GRUB_CFG}.new"
        mv "${GRUB_CFG}.new" "$GRUB_CFG"
        echo "✅ Added serial settings to grub.cfg"
    else
        echo "ℹ️  Serial settings already in grub.cfg"
    fi
else
    echo "⚠️  $GRUB_CFG not found!"
fi

# 2. Patch BLS entries
for conf in "$BLS_DIR"/*.conf; do
    if [ -f "$conf" ]; then
        echo "📄 Patching BLS entry: $(basename "$conf")"
        cp "$conf" "${conf}.bak"
        
        # Append console=ttyS0 and edd=off to options line if missing
        if grep -q "^options" "$conf"; then
            if ! grep -q "console=ttyS0" "$conf"; then
                sed -i '/^options/ s/$/ console=ttyS0/' "$conf"
                echo "  ➕ Added console=ttyS0"
            fi
            if ! grep -q "edd=off" "$conf"; then
                sed -i '/^options/ s/$/ edd=off/' "$conf"
                echo "  ➕ Added edd=off"
            fi
            # Remove quiet/rhgb if present to see boot messages
            sed -i 's/ quiet//g' "$conf"
            sed -i 's/ rhgb//g' "$conf"
        fi
    fi
done

echo "✅ Patching complete."
