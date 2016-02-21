#! /bin/sh

if [ -z "$1" ]; then
    echo "No version provided. Abort."
    exit 1
fi

cp ./sensor/bin/macosx/*/x86_64/debug/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_osx_x64_debug_$1"
cp ./sensor/bin/macosx/*/x86_64/release/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_osx_x64_release_$1"
cp ./sensor/bin/ubuntu/*/x86_64/debug/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_ubuntu_x64_debug_$1"
cp ./sensor/bin/ubuntu/*/x86_64/release/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_ubuntu_x64_release_$1"
cp ./sensor/bin/Win32/Debug/rphcp.exe "./prebuilt_binaries/hcp_win_x86_debug_$1.exe"
cp ./sensor/bin/Win32/Release/rphcp.exe "./prebuilt_binaries/hcp_win_x86_release_$1.exe"
cp ./sensor/bin/x64/Debug/rphcp.exe "./prebuilt_binaries/hcp_win_x64_debug_$1.exe"
cp ./sensor/bin/x64/Release/rphcp.exe "./prebuilt_binaries/hcp_win_x64_release_$1.exe"
cp ./sensor/bin/macosx/*/x86_64/debug/librpHCP_HostBasedSensor.dylib "./prebuilt_binaries/hbs_osx_x64_debug_$1.dylib"
cp ./sensor/bin/macosx/*/x86_64/release/librpHCP_HostBasedSensor.dylib "./prebuilt_binaries/hbs_osx_x64_release_$1.dylib"
cp ./sensor/bin/ubuntu/*/x86_64/debug/librpHCP_HostBasedSensor.so "./prebuilt_binaries/hbs_ubuntu_x64_debug_$1.so"
cp ./sensor/bin/ubuntu/*/x86_64/release/librpHCP_HostBasedSensor.so "./prebuilt_binaries/hbs_ubuntu_x64_release_$1.so"
cp ./sensor/bin/Win32/Debug/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x86_debug_$1.dll"
cp ./sensor/bin/Win32/Release/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x86_release_$1.dll"
cp ./sensor/bin/x64/Debug/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x64_debug_$1.dll"
cp ./sensor/bin/x64/Release/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x64_release_$1.dll"


cp "./prebuilt_binaries/hcp_osx_x64_debug_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/osx_debug_x64_$1_installer.run "LIMA CHARLIE $1 OSX x64 Debug Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./prebuilt_binaries/hcp_osx_x64_release_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/osx_release_x64_$1_installer.run "LIMA CHARLIE $1 OSX x64 Release Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./prebuilt_binaries/hcp_ubuntu_x64_debug_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/ubuntu_debug_x64_$1_installer.run "LIMA CHARLIE $1 Ubuntu x64 Debug Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./prebuilt_binaries/hcp_ubuntu_x64_release_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/ubuntu_release_x64_$1_installer.run "LIMA CHARLIE $1 Ubuntu x64 Release Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin
