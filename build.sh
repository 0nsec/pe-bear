#!/bin/bash

./build_qt6.sh

# Install to system (requires sudo)
if [ "$1" = "install" ]; then
    echo "[+] Installing PE-bear to system..."
    
    # Copy binary
    sudo cp build_qt6/bin/PE-bear /usr/local/bin/PE-bear
    echo "[+] Binary installed to /usr/local/bin/PE-bear"
    
    # Copy desktop file for launcher
    sudo cp build_qt6/share/applications/net.hasherezade.pe-bear.desktop /usr/share/applications/
    echo "[+] Desktop launcher installed"
    
    # Copy icon
    sudo cp build_qt6/share/pixmaps/net.hasherezade.pe-bear.png /usr/share/pixmaps/
    echo "[+] Icon installed"
    
    # Copy metainfo
    sudo cp build_qt6/share/metainfo/net.hasherezade.pe-bear.metainfo.xml /usr/share/metainfo/
    echo "[+] Metainfo installed"
    
    # Update desktop database
    sudo update-desktop-database /usr/share/applications 2>/dev/null
    echo "[+] Desktop database updated"
    
    echo "[+] Installation complete! PE-bear should now appear in your application launcher."
fi
