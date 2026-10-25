# 🐊 NetSentry Extension - Installation Guide

**Created by: ABHISHEK**  
**Version: 1.0**  
**Year: 2026**

## Quick Start

### Method 1: Load Unpacked Extension (Recommended for Testing)

1. **Download the Extension**
   - Download the `netsentry-extension.zip` file
   - Extract it to a folder on your computer

2. **Open Chrome Extensions Page**
   - Open Google Chrome
   - Navigate to `chrome://extensions/`
   - Or click the three dots menu → More tools → Extensions

3. **Enable Developer Mode**
   - Toggle "Developer mode" ON in the top-right corner

4. **Load the Extension**
   - Click "Load unpacked"
   - Select the extracted extension folder (should contain `manifest.json`)
   - Click "Select Folder"

5. **Verify Installation**
   - The extension should appear in your extensions list
   - You should see a shield icon in your browser toolbar
   - Click the icon to open the popup interface

### Method 2: Using the Build Directory

If you cloned the repository:

1. **Navigate to Build Directory**
   ```bash
   cd build/
   ```

2. **Follow Steps 2-5 from Method 1**
   - Load the `build/` directory as an unpacked extension

## 📋 Prerequisites

- **Google Chrome** version 88 or higher
- **Microsoft Edge** (Chromium-based) version 88 or higher
- **Developer mode** enabled for unpacked extensions

## 🔧 Configuration

### Initial Setup

1. **Grant Permissions**
   - The extension will request several permissions on first use
   - Click "Allow" for all permission requests

2. **Test Basic Functionality**
   - Visit a safe site like `https://google.com`
   - Click the extension icon
   - Verify you see a security analysis

### Icon Display Issues

If icons don't display properly:

1. **Convert SVG to PNG**
   - Use online converters like:
     - convertio.co
     - svgtopng.com
     - cloudconvert.com
   - Convert all SVG files in the `icons/` folder
   - Replace the existing PNG files

2. **Manual Icon Creation**
   - Create 16x16, 32x32, 48x48, and 128x128 PNG icons
   - Use a blue shield design with a checkmark
   - Save as `icon16.png`, `icon32.png`, `icon48.png`, `icon128.png`

## 🧪 Testing the Extension

### Quick Test

1. **Visit Safe Sites**
   - Go to `https://google.com`
   - Extension should show low risk (green indicator)

2. **Test Popup Interface**
   - Click the extension icon
   - Should show security analysis
   - Try "Trust Site" and "Report Phishing" buttons

3. **Check Console Logs**
   - Press F12 to open Developer Tools
   - Check Console tab for extension logs
   - Look for "NetSentry:" messages

### Advanced Testing

See `test_sites.md` for comprehensive testing scenarios.

## 🛠️ Troubleshooting

### Extension Won't Load

**Error: "Manifest file is missing or unreadable"**
- Ensure you selected the correct folder containing `manifest.json`
- Check that the file isn't corrupted

**Error: "This extension may have been corrupted"**
- Re-extract the ZIP file
- Ensure all files are present
- Try loading a fresh copy

### Extension Loads But Doesn't Work

**No icon in toolbar**
- Check if Chrome blocked the extension
- Look for error messages in `chrome://extensions/`
- Verify manifest.json syntax

**Content script not running**
- Check browser console for JavaScript errors
- Verify the extension has necessary permissions
- Try reloading the extension

**Background script issues**
- Go to `chrome://extensions/`
- Click "Details" on the NetSentry
- Click "Inspect views: service worker"
- Check for errors in the console

### Permission Issues

**Extension can't access websites**
- Ensure you granted all requested permissions
- Check if any security software is blocking the extension
- Try disabling other extensions temporarily

## 🔄 Updating the Extension

### For Development Versions

1. Make changes to the source files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the NetSentry extension
4. Or click "Remove" and reload the updated folder

### Keeping Extensions Current

- This extension is not auto-updating (developer version)
- Check for updates manually by downloading new versions
- Remove old version before installing new one

## 🚫 Uninstalling

1. **Remove from Chrome**
   - Go to `chrome://extensions/`
   - Find "NetSentry"
   - Click "Remove"
   - Confirm removal

2. **Clean Up Files**
   - Delete the extension folder from your computer
   - Clear any browser data if desired

## 🔐 Privacy & Security Notes

### Data Handling
- All analysis is performed locally on your device
- No data is sent to external servers
- Extension only stores whitelists and statistics locally

### Permissions Explanation
- **activeTab**: Read current page URL for analysis
- **tabs**: Monitor navigation for protection
- **storage**: Save settings and whitelist
- **webNavigation**: Detect page loads
- **<all_urls>**: Analyze any website for threats

## 📞 Support

### Getting Help

1. **Check Console Logs**
   - Press F12 → Console tab
   - Look for error messages

2. **Extension Details**
   - Go to `chrome://extensions/`
   - Click "Details" on NetSentry
   - Check for error messages

3. **Common Solutions**
   - Restart Chrome
   - Reload the extension
   - Clear browser cache
   - Try incognito mode

### Known Limitations

- SVG icons may not display properly (convert to PNG)
- Some advanced Chrome features may not work in all browsers
- Performance may vary on very old devices

## 📈 Performance Tips

### For Best Performance
- Keep browser updated
- Don't run too many extensions simultaneously
- Clear browser cache regularly
- Monitor extension's memory usage in Task Manager

### Resource Usage
- The extension is lightweight and efficient
- Minimal impact on browsing speed
- Uses local processing only

---

## 🎯 Next Steps After Installation

1. **Read the Documentation**
   - Check `README.md` for detailed features
   - Review `test_sites.md` for testing guidance

2. **Customize Settings**
   - Add trusted sites to whitelist
   - Test reporting functionality

3. **Stay Safe Online**
   - Use the extension as one layer of protection
   - Keep learning about phishing techniques
   - Always verify suspicious emails and links

**Happy and Safe Browsing! 🐊**