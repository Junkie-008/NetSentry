# NetSentry Browser Extension

**Created by: ABHISHEK**  
**Version: 1.1**  
**Year: 2026**

A comprehensive Chrome extension designed to protect users from phishing attacks through real-time URL analysis, suspicious pattern detection, and advanced security features.

## 🐊 Features

### Real-time Protection
- **URL Analysis**: Automatically analyzes every website you visit for potential phishing threats
- **Risk Scoring**: Assigns risk scores (0-100) based on multiple factors
- **Instant Blocking**: Automatically blocks high-risk sites (score > 70)
- **Warning System**: Shows warnings for medium-risk sites (score 40-70)

### Advanced Detection Methods
- **Domain Analysis**: Detects suspicious domain patterns, homograph attacks, and brand impersonation
- **Content Scanning**: Analyzes page content for phishing keywords and patterns
- **Form Security**: Monitors forms collecting sensitive information on non-HTTPS sites
- **Link Verification**: Checks for misleading links and URL shorteners
- **SSL Certificate Validation**: Ensures secure connections for sensitive data

### User Interface
- **Beautiful Popup**: Modern, intuitive interface showing security status
- **Visual Indicators**: Color-coded badges and warnings
- **Security Flags**: Detailed breakdown of security concerns
- **Statistics Tracking**: Monitor blocked sites and detected threats

### Smart Features
- **Whitelist System**: Trust specific domains
- **Reporting System**: Report new phishing sites
- **Dynamic Analysis**: Real-time monitoring of page changes
- **Background Protection**: Continuous monitoring without performance impact

## 🚀 Installation

### For Development/Testing:

1. **Download the Extension**
   ```bash
   git clone <repository-url>
   cd netsentry-extension
   ```

2. **Load in Chrome**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode" in the top right
   - Click "Load unpacked" and select the extension folder
   - The extension will appear in your browser toolbar

3. **Grant Permissions**
   - The extension will request permissions for:
     - Reading and changing data on all websites
     - Managing tabs and navigation
     - Storing data locally

## 🔧 How It Works

### Risk Assessment Algorithm

The extension uses a sophisticated multi-factor analysis system:

#### Domain Analysis (0-35 points)
- Suspicious TLDs (.tk, .ml, .ga, etc.)
- Excessive subdomains
- Mixed digits and letters
- Homograph attack detection
- Brand impersonation patterns

#### URL Structure Analysis (0-30 points)
- URL shorteners detection
- Suspicious path patterns
- Excessive URL length
- Redirection indicators

#### Content Pattern Analysis (0-35 points)
- Phishing keywords detection
- Urgency language patterns
- Security verification requests
- Fake authentication prompts

### Risk Levels

- **0-20**: ✅ Safe Site
- **21-40**: 🔒 Low Risk
- **41-70**: ⚠️ Medium Risk - Show Warning
- **71-100**: 🚫 High Risk - Block Access

## 🎯 Usage

### Automatic Protection
The extension works automatically in the background:
- Visit any website
- Extension analyzes the site in real-time
- Receive warnings or blocks for suspicious sites
- View security status in the popup

### Manual Actions
- **Report Phishing**: Click to report suspicious sites
- **Trust Site**: Add legitimate sites to whitelist
- **View Details**: See detailed security analysis
- **Check Statistics**: Monitor protection activity

## 🛠️ Configuration

### Whitelist Management
Add trusted domains that should never be flagged:
- Click the extension icon
- Click "Trust Site" for current domain
- Or manually add domains in extension settings

### Sensitivity Settings
The extension uses predefined thresholds:
- Warning threshold: 40 points
- Blocking threshold: 70 points
- These can be adjusted in the code if needed

## 📊 Technical Details

### Architecture
- **Manifest V3**: Uses the latest Chrome extension standards
- **Service Worker**: Background processing for continuous protection
- **Content Scripts**: Real-time page analysis
- **Storage API**: Local data persistence

### Performance
- **Lightweight**: Minimal impact on browsing speed
- **Efficient**: Smart caching and optimized algorithms
- **Privacy-Focused**: All analysis done locally, no data sent to external servers

### Browser Compatibility
- Chrome (Manifest V3)
- Edge (Chromium-based)
- Other Chromium-based browsers

## 🔒 Privacy & Security

### Data Handling
- **Local Only**: All analysis performed locally on your device
- **No External Calls**: No data sent to remote servers
- **Minimal Storage**: Only stores necessary security data
- **User Control**: Full control over whitelists and settings

### Permissions Explained
- **activeTab**: Read current tab URL for analysis
- **tabs**: Monitor tab changes for protection
- **storage**: Save whitelists and statistics
- **webNavigation**: Detect navigation events
- **<all_urls>**: Analyze any website for threats

## 🧪 Testing

### Automated Test Suite

The project ships with a four-level test suite (Node's built-in test runner,
no global dependencies needed):

```bash
npm install       # dev dependencies (jsdom, puppeteer-core)npm test          # everything
npm run test:unit         # positive / negative / boundary / edge cases
npm run test:integration    # background worker + content script in jsdom
npm run test:system         # manifest/build validation + headless Chrome E2E
npm run test:acceptance     # README / test docs promises verified in code
```

| Level | Location | What it verifies |
|-------|----------|------------------|
| Unit | `tests/unit/` | Scoring engine: positive, negative, boundary (20/21, 40/41, 70/71, 30/31-char domain, 3/4 subdomains, 100/101-char URL) and edge cases (invalid URLs, IP hosts, punycode, 10KB URLs) |
| Performance | `tests/unit/performance.test.js` | 10k URLs/second-class throughput, no regex backtracking on 120KB pathological input |
| Integration | `tests/integration/` | Real `background.js`/`content.js` driven through mocked `chrome.*` APIs and jsdom pages, including the `document_start` (null `document.body`) path |
| System | `tests/system/` | Manifest consistency, `build.sh` output, and a live end-to-end run: the extension loaded into headless Chrome blocks/warns real pages |
| Acceptance | `tests/acceptance/` | Every documented claim in `README.md`, `test_sites.md` and `test_paypal_detection.html` (thresholds, risk bands, score expectations, privacy) |

### Test Cases
The extension detects various phishing techniques:
- Domain spoofing (e.g., goog1e.com instead of google.com)
- Subdomain attacks (e.g., google.com.evil-site.com)
- Homograph attacks using similar-looking characters
- Suspicious TLDs and domain patterns
- Phishing keywords and urgent language
- Insecure forms collecting sensitive data

### Safe Testing
- Extension includes major legitimate domains in whitelist
- Test with known safe sites to verify proper operation
- Use developer tools to monitor extension behavior

## 🤝 Contributing

### Development Setup
1. Clone the repository
2. Make changes to the source files
3. Test in Chrome developer mode
4. Submit pull requests for improvements

### Reporting Issues
- Use GitHub issues for bug reports
- Include steps to reproduce
- Provide extension logs if available

## 👨‍💻 Author

**ABHISHEK**  
- Creator and Lead Developer
- Security Software Specialist
- Year: 2026

## 📝 License

This project is created by ABHISHEK and is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This extension provides an additional layer of security but should not be your only protection against phishing. Always:
- Keep your browser updated
- Use strong, unique passwords
- Enable two-factor authentication
- Stay informed about current phishing techniques
- Trust your instincts when something seems suspicious

## 🔮 Future Enhancements

- Machine learning-based detection
- Integration with threat intelligence feeds
- Advanced certificate analysis
- Social engineering detection
- Mobile browser support
- Enterprise management features

---

**Stay Safe Online! 🐊**

*"Protecting users from phishing attacks through innovative browser security technology."*  
**- ABHISHEK, Creator & Developer, 2026**

For support or questions about this extension created by ABHISHEK, please refer to the documentation or open an issue on GitHub.
# NetSentry
