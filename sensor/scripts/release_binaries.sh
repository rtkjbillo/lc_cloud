#! /bin/sh

if [ -z "$1" ]; then
    echo "No version provided. Abort."
    exit 1
fi

cp ./sensor/bin/macosx/*/x86_64/debug/rpHostCommonPlatformExe "./binary_releases/hcp_osx_x64_debug_$1"
cp ./sensor/bin/macosx/*/x86_64/release/rpHostCommonPlatformExe "./binary_releases/hcp_osx_x64_release_$1"
cp ./sensor/bin/ubuntu/*/x86_64/debug/rpHostCommonPlatformExe "./binary_releases/hcp_ubuntu_x64_debug_$1"
cp ./sensor/bin/ubuntu/*/x86_64/release/rpHostCommonPlatformExe "./binary_releases/hcp_ubuntu_x64_release_$1"
cp ./sensor/bin/Win32/Debug/rphcp.exe "./binary_releases/hcp_win_x86_debug_$1.exe"
cp ./sensor/bin/Win32/Release/rphcp.exe "./binary_releases/hcp_win_x86_release_$1.exe"
cp ./sensor/bin/x64/Debug/rphcp.exe "./binary_releases/hcp_win_x64_debug_$1.exe"
cp ./sensor/bin/x64/Release/rphcp.exe "./binary_releases/hcp_win_x64_release_$1.exe"
cp ./sensor/bin/macosx/*/x86_64/debug/librpHCP_HostBasedSensor.dylib "./binary_releases/hbs_osx_x64_debug_$1.dylib"
cp ./sensor/bin/macosx/*/x86_64/release/librpHCP_HostBasedSensor.dylib "./binary_releases/hbs_osx_x64_release_$1.dylib"
cp ./sensor/bin/ubuntu/*/x86_64/debug/librpHCP_HostBasedSensor.so "./binary_releases/hbs_ubuntu_x64_debug_$1.so"
cp ./sensor/bin/ubuntu/*/x86_64/release/librpHCP_HostBasedSensor.so "./binary_releases/hbs_ubuntu_x64_release_$1.so"
cp ./sensor/bin/Win32/Debug/rpHCP_HostBasedSensor.dll "./binary_releases/hbs_win_x86_debug_$1.dll"
cp ./sensor/bin/Win32/Release/rpHCP_HostBasedSensor.dll "./binary_releases/hbs_win_x86_release_$1.dll"
cp ./sensor/bin/x64/Debug/rpHCP_HostBasedSensor.dll "./binary_releases/hbs_win_x64_debug_$1.dll"
cp ./sensor/bin/x64/Release/rpHCP_HostBasedSensor.dll "./binary_releases/hbs_win_x64_release_$1.dll"


cp "./binary_releases/hcp_osx_x64_debug_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./binary_releases/osx_debug_x64_installer.run "LIMA CHARLIE $1 OSX x64 Debug Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./binary_releases/hcp_osx_x64_release_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./binary_releases/osx_release_x64_installer.run "LIMA CHARLIE $1 OSX x64 Release Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./binary_releases/hcp_ubuntu_x64_debug_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./binary_releases/ubuntu_debug_x64_installer.run "LIMA CHARLIE $1 Ubuntu x64 Debug Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./binary_releases/hcp_ubuntu_x64_release_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./binary_releases/ubuntu_release_x64_installer.run "LIMA CHARLIE $1 Ubuntu x64 Release Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin
