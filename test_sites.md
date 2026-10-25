# Test Sites for NetSentry

**Created by: ABHISHEK**  
**Version: 1.0**  
**Year: 2026**

This file contains various test cases to verify the phishing detection functionality.

## ✅ Safe Sites (Should show low risk scores)

These sites should be detected as safe with low risk scores:

- https://google.com
- https://github.com
- https://stackoverflow.com
- https://wikipedia.org
- https://microsoft.com
- https://amazon.com

## ⚠️ Medium Risk Patterns (Should trigger warnings)

Risk points accumulate - a single signal rarely crosses the warning
threshold (score > 40) on its own:

### URL Shorteners (+25)
- bit.ly links
- tinyurl.com links
- t.co links

Combine with a redirect parameter (+15) or phishing phrase (+20) to cross
the warning threshold.

### Suspicious Domain Patterns
- Excessive subdomains, 4+ (`test.example.subdomain.domain.com`) - +45,
  warns on its own
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq) - +45, warns on its own
- Very long domain names (> 30 chars) - +15 contributing factor
- Domains mixing numbers and letters - +10 contributing factor

### Insecure Connections
- HTTP on a login/security-related host - +40 contributing factor

## 🚫 High Risk Patterns (Should be blocked, score > 70)

### Brand Impersonation
- paypal-security.com (fake PayPal) - 80
- amazon-verification.net (fake Amazon) - 75
- google-accounts.info (fake Google) - 75
- paypa1-login.com / payp4l.example (character substitution) - 80
- g00gle.com (character substitution) - 75

### Punycode / Homograph Domains (+40, combine with other signals)
- xn--ggle-55da.com (punycode google look-alike)

### Phishing Keywords (page content, flagged by the content script)
Pages containing these phrases should trigger alerts:
- "verify your account immediately"
- "account suspended"
- "click here immediately"
- "urgent action required"
- "update payment information"
- "suspicious activity detected"

## 🧪 Testing Instructions

1. **Install the Extension**
   - Load the extension in Chrome developer mode
   - Grant all required permissions

2. **Test Safe Sites**
   - Visit known safe sites
   - Verify low risk scores (0-20)
   - Check for green safety indicators

3. **Test Warning Triggers**
   - Create test pages with suspicious patterns
   - Verify medium risk warnings appear
   - Test dismissing warnings

4. **Test Blocking**
   - Create test pages with high-risk patterns
   - Verify sites are blocked
   - Test "Go Back" functionality

5. **Test Form Security**
   - Create HTTP pages with password forms
   - Verify security warnings appear
   - Test form submission warnings

6. **Test Extension Popup**
   - Click extension icon on various sites
   - Verify risk scores are displayed correctly
   - Test "Report Phishing" and "Trust Site" buttons

## 🛠️ Developer Testing

### Console Logging
Check browser console for:
- Phishing detection logs
- Error messages
- Performance metrics

### Storage Testing
Verify extension storage:
```javascript
chrome.storage.local.get(null, console.log);
```

### Background Script Testing
Monitor background script activity:
- Tab change detection
- URL analysis triggers
- Risk score calculations

## 🔍 Manual Test Scenarios

### Test Case 1: Safe Site Navigation
1. Visit https://google.com
2. Extension should show green indicator
3. Risk score should be 0-20
4. No warnings should appear

### Test Case 2: Suspicious Link Detection
1. Create page with misleading links
2. Links should be highlighted
3. Click warnings should appear

### Test Case 3: Form Security Check
1. Create HTTP page with login form
2. Form should be marked as insecure
3. Submission warning should appear

### Test Case 4: Phishing Site Block
1. Create page with multiple high-risk factors
2. Site should be blocked immediately
3. User should see blocking page

### Test Case 5: Whitelist Functionality
1. Add site to whitelist
2. Risk score should become 0
3. No warnings should appear

## 📊 Expected Results

### Safe Sites
- Risk Score: 0-20
- Badge: none (or slate #415A77)
- Status: "Safe Site" or "Low Risk"

### Medium Risk Sites
- Risk Score: 41-70
- Badge: "?" on mid-slate (#778DA9)
- Status: "Medium Risk - Be Cautious"
- Action: Warning overlay

### High Risk Sites
- Risk Score: 71-100
- Badge: "!" on off-white (#E0E1DD)
- Status: "High Risk - Potential Phishing"
- Action: Site blocked

## 🐛 Common Issues & Troubleshooting

### Extension Not Loading
- Check manifest.json syntax
- Verify all files are present
- Check Chrome developer console

### Icons Not Displaying
- Convert SVG icons to PNG format
- Verify icon file paths in manifest
- Check file permissions

### Content Script Not Running
- Verify content script matches in manifest
- Check for JavaScript errors
- Test on different page types

### Background Script Issues
- Monitor service worker in Chrome DevTools
- Check for permission issues
- Verify event listeners are registered

## 📝 Notes

- Test on both HTTP and HTTPS sites
- Try different browser zoom levels
- Test with various screen sizes
- Check mobile browser compatibility (if applicable)
- Verify performance on slow connections

Remember: This is a security tool, so thorough testing is crucial for user safety!