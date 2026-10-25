#!/bin/bash

# NetSentry Extension Build Script
# Created by: ABHISHEK
# Version: 1.1
# Year: 2026

echo "🐊 Building NetSentry Extension..."

# Create build directory
mkdir -p build
rm -rf build/*

# Copy extension files
echo "📁 Copying extension files..."
cp manifest.json build/
cp detector.js build/
cp background.js build/
cp content.js build/
cp popup.html build/
cp popup.js build/
cp blocked.html build/
cp blocked.js build/
cp styles.css build/

# Copy documentation and credits
echo "📄 Copying documentation..."
cp README.md build/
cp LICENSE build/
cp CREDITS.md build/
cp INSTALLATION.md build/

# Copy icons (create from SVG if needed)
echo "🎨 Processing icons..."
mkdir -p build/icons

# Check if we have proper PNG files, if not copy SVG files
if [ -f "icons/icon16.png" ] && [ -s "icons/icon16.png" ]; then
    cp icons/*.png build/icons/
    echo "✅ PNG icons copied"
else
    echo "⚠️  PNG icons not found, copying SVG files instead"
    cp icons/*.svg build/icons/
    echo "📝 Note: You'll need to convert SVG to PNG for the extension to work properly"
fi

# Create package info
echo "📦 Creating package info..."
cat > build/package_info.txt << EOF
NetSentry Browser Extension
==================================

Created by: ABHISHEK
Build Date: $(date)
Version: 1.1

Files included:
- manifest.json (Extension configuration)
- detector.js (Shared detection engine, unit-tested)
- background.js (Background service worker)
- content.js (Content script for page analysis)
- popup.html (Extension popup interface)
- popup.js (Popup functionality)
- blocked.html + blocked.js (Hardened block page, redirect target)
- styles.css (Content script styles)
- icons/ (Extension icons)
- README.md (Complete documentation)
- LICENSE (MIT License - ABHISHEK)
- CREDITS.md (Creator attribution)
- INSTALLATION.md (Installation guide)

Installation Instructions:
1. Open Chrome/Edge
2. Navigate to chrome://extensions/
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select this build folder

Note: If using SVG icons, convert them to PNG format for proper display.
EOF

# Create zip package
echo "📦 Creating extension package..."
rm -f netsentry-extension.zip 2>/dev/null || true
if command -v zip >/dev/null 2>&1; then
    cd build
    zip -r ../netsentry-extension.zip . > /dev/null 2>&1
    cd ..
elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command "Compress-Archive -Force -Path 'build/*' -DestinationPath 'netsentry-extension.zip'" > /dev/null 2>&1
    echo "📝 zip not found - used PowerShell Compress-Archive instead"
else
    echo "⚠️  Neither zip nor PowerShell found - skipping package step"
fi

echo "✅ Build complete!"
echo ""
echo "📁 Build output: ./build/"
echo "📦 Package: ./netsentry-extension.zip"
echo ""
echo "🚀 Next steps:"
echo "1. Load the extension in Chrome developer mode"
echo "2. Test on various websites"
echo "3. Convert SVG icons to PNG if needed"
echo ""
echo "🐊 Stay safe online!"