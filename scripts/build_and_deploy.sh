#!/bin/bash

echo "Building RemoteManager with TEE support..."

# 设置环境
source build/envsetup.sh
lunch aosp_car_x86_64-userdebug

# 编译模块
echo "Building remote-manager-proto..."
mmm packages/services/Car/RemoteManager/remote-manager-proto

echo "Building RemoteManagerApp..."
mmm packages/services/Car/RemoteManager

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo ""
    echo "TEE Storage Features:"
    echo "✓ Client_secret stored in Android Keystore TEE"
    echo "✓ AES-256-GCM encryption with hardware-backed keys"
    echo "✓ StrongBox support for enhanced security"
    echo "✓ Fallback to in-memory storage if TEE unavailable"
    echo ""
    echo "To deploy:"
    echo "  adb root"
    echo "  adb remount" 
    echo "  adb sync"
    echo "  adb reboot"
else
    echo "Build failed!"
    exit 1
fi
