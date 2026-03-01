// Origami Phishing/Malicious Site Reporter
// Allows users to report suspected malicious websites to multiple security vendors

class PhishingReporter {
  constructor() {
    this.vendors = [
      {
        id: 'google-safebrowsing',
        name: 'Google Safe Browsing',
        icon: 'shield',
        description: 'Report to Google Safe Browsing for Chrome/Firefox protection',
        reportUrl: (url) => `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`,
        type: 'redirect'
      },
      {
        id: 'phishtank',
        name: 'PhishTank',
        icon: 'search',
        description: 'Community-driven phishing verification and reporting',
        reportUrl: (url) => `https://phishtank.org/add_web_phishing.php?url=${encodeURIComponent(url)}`,
        type: 'redirect'
      },
      {
        id: 'microsoft-smartscreen',
        name: 'Microsoft SmartScreen',
        icon: 'shield',
        description: 'Report to Microsoft Defender SmartScreen for Edge/Windows protection',
        reportUrl: (url) => `https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest`,
        type: 'redirect'
      },
      {
        id: 'cloudflare-radar',
        name: 'Cloudflare Radar',
        icon: 'globe',
        description: 'Submit URL for scanning and analysis via Cloudflare Radar',
        reportUrl: (url) => `https://radar.cloudflare.com/scan?url=${encodeURIComponent(url)}`,
        type: 'redirect'
      },
      {
        id: 'apwg',
        name: 'APWG',
        icon: 'alert',
        description: 'Report to the Anti-Phishing Working Group',
        reportUrl: (url) => `https://apwg.org/reportphishing/`,
        type: 'redirect'
      },
      {
        id: 'abuse-ch',
        name: 'abuse.ch URLhaus',
        icon: 'warning',
        description: 'Submit malicious URL to URLhaus threat intelligence',
        reportUrl: (url) => `https://urlhaus.abuse.ch/browse/`,
        type: 'redirect'
      },
      {
        id: 'virustotal',
        name: 'VirusTotal',
        icon: 'search',
        description: 'Check and submit URL for multi-engine scanning',
        reportUrl: (url) => `https://www.virustotal.com/gui/home/url`,
        type: 'redirect'
      },
      {
        id: 'netcraft',
        name: 'Netcraft',
        icon: 'shield',
        description: 'Report phishing or malicious site to Netcraft',
        reportUrl: (url) => `https://report.netcraft.com/report?url=${encodeURIComponent(url)}`,
        type: 'redirect'
      }
    ];

    this.categories = [
      { id: 'phishing', name: 'Phishing', description: 'Fake login pages or credential harvesting' },
      { id: 'malware', name: 'Malware', description: 'Distributes malicious software' },
      { id: 'scam', name: 'Scam', description: 'Fraudulent schemes or deceptive content' },
      { id: 'spam', name: 'Spam', description: 'Unsolicited or misleading content' },
      { id: 'other', name: 'Other', description: 'Other malicious or suspicious activity' }
    ];
  }

  getVendors() {
    return this.vendors;
  }

  getVendorById(vendorId) {
    return this.vendors.find(v => v.id === vendorId);
  }

  getCategories() {
    return this.categories;
  }

  getReportUrl(vendorId, targetUrl) {
    const vendor = this.getVendorById(vendorId);
    if (!vendor) return null;
    return vendor.reportUrl(targetUrl);
  }

  createReport(targetUrl, vendorId, category, notes) {
    return {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      targetUrl: targetUrl,
      vendorId: vendorId,
      vendorName: this.getVendorById(vendorId)?.name || vendorId,
      category: category,
      notes: notes || '',
      timestamp: new Date().toISOString(),
      status: 'submitted'
    };
  }

  async saveReport(report) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.get(['origami_report_history'], (data) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
          return;
        }
        const history = data.origami_report_history || [];
        history.unshift(report);
        // Keep only last 200 reports
        if (history.length > 200) {
          history.length = 200;
        }
        chrome.storage.local.set({ origami_report_history: history }, () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(history);
          }
        });
      });
    });
  }

  async getReportHistory() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['origami_report_history'], (data) => {
        resolve(data.origami_report_history || []);
      });
    });
  }

  async clearReportHistory() {
    return new Promise((resolve) => {
      chrome.storage.local.set({ origami_report_history: [] }, () => {
        resolve([]);
      });
    });
  }
}

// Singleton instance
const phishingReporter = new PhishingReporter();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PhishingReporter, phishingReporter };
}
