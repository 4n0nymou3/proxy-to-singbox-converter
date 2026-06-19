const SUPPORTED_PROTOCOLS = ['vmess://', 'vless://', 'trojan://', 'hysteria2://', 'hy2://', 'ss://'];
const CORS_PROXIES = [
    'https://api.allorigins.win/get?url=',
    'https://corsproxy.io/?',
    'https://cors-anywhere.herokuapp.com/',
    'https://api.codetabs.com/v1/proxy?quest=',
    'https://cors-proxy.htmldriven.com/?url=',
    'https://thingproxy.freeboard.io/fetch/'
];

function isLink(str) {
    return str.startsWith('http://') || str.startsWith('https://') || str.startsWith('ssconf://');
}

function isGoogleDriveLink(url) {
    return url.includes('drive.google.com');
}

function extractGoogleDriveId(url) {
    if (url.includes('id=')) {
        const idMatch = url.match(/id=([^&]+)/);
        if (idMatch && idMatch[1]) {
            return idMatch[1];
        }
    }
    
    if (url.includes('/d/')) {
        const idMatch = url.match(/\/d\/([^/]+)/);
        if (idMatch && idMatch[1]) {
            return idMatch[1];
        }
    }
    
    return null;
}

function isBase64(str) {
    if (!str || str.length % 4 !== 0) return false;
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    return base64Regex.test(str);
}

function isDataUriBase64(str) {
    return str.startsWith('data:') && str.includes('base64,');
}

function extractBase64FromDataUri(str) {
    const base64Part = str.split('base64,')[1];
    if (base64Part) {
        return base64Part;
    }
    return str;
}

async function fetchContent(link) {
    if (link.startsWith('ssconf://')) {
        link = link.replace('ssconf://', 'https://');
    }
    
    if (isGoogleDriveLink(link)) {
        const driveId = extractGoogleDriveId(link);
        if (driveId) {
            const directDownloadUrl = `https://drive.google.com/uc?export=download&id=${driveId}`;
            try {
                return await fetchWithFallbacks(directDownloadUrl);
            } catch (error) {
                console.error(`Failed to fetch Google Drive content:`, error);
                return null;
            }
        }
    }
    
    return await fetchWithFallbacks(link);
}

async function fetchWithFallbacks(url) {
    try {
        const response = await fetch(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        let text = await response.text();
        text = text.trim();
        
        if (isDataUriBase64(text)) {
            const base64Content = extractBase64FromDataUri(text);
            try {
                return atob(base64Content);
            } catch (e) {
                console.error(`Failed to decode Base64 from data URI:`, e);
            }
        }
        
        if (isBase64(text)) {
            try {
                return atob(text);
            } catch (e) {
                console.error(`Failed to decode Base64:`, e);
            }
        }
        
        return text;
    } catch (error) {
        console.error(`Failed to fetch ${url} directly:`, error);
        
        for (const proxyUrl of CORS_PROXIES) {
            try {
                let fullProxyUrl;
                
                if (proxyUrl === CORS_PROXIES[0]) {
                    fullProxyUrl = `${proxyUrl}${encodeURIComponent(url)}`;
                    const response = await fetch(fullProxyUrl);
                    if (!response.ok) {
                        throw new Error(`HTTP error with ${proxyUrl}! status: ${response.status}`);
                    }
                    const data = await response.json();
                    let text = data.contents.trim();
                    
                    if (isDataUriBase64(text)) {
                        const base64Content = extractBase64FromDataUri(text);
                        try {
                            return atob(base64Content);
                        } catch (e) {
                            console.error(`Failed to decode Base64 from data URI via ${proxyUrl}:`, e);
                        }
                    }
                    
                    if (isBase64(text)) {
                        try {
                            return atob(text);
                        } catch (e) {
                            console.error(`Failed to decode Base64 from ${url} via ${proxyUrl}:`, e);
                        }
                    }
                    
                    return text;
                } else {
                    fullProxyUrl = `${proxyUrl}${encodeURIComponent(url)}`;
                    const response = await fetch(fullProxyUrl);
                    if (!response.ok) {
                        throw new Error(`HTTP error with ${proxyUrl}! status: ${response.status}`);
                    }
                    let text = await response.text();
                    text = text.trim();
                    
                    if (isDataUriBase64(text)) {
                        const base64Content = extractBase64FromDataUri(text);
                        try {
                            return atob(base64Content);
                        } catch (e) {
                            console.error(`Failed to decode Base64 from data URI via ${proxyUrl}:`, e);
                        }
                    }
                    
                    if (isBase64(text)) {
                        try {
                            return atob(text);
                        } catch (e) {
                            console.error(`Failed to decode Base64 from ${url} via ${proxyUrl}:`, e);
                        }
                    }
                    
                    return text;
                }
            } catch (proxyError) {
                console.error(`Failed to fetch ${url} via ${proxyUrl}:`, proxyError);
                continue;
            }
        }
        
        if (isGoogleDriveLink(url)) {
            const driveId = extractGoogleDriveId(url);
            if (driveId) {
                try {
                    const alternateUrl = `https://www.googleapis.com/drive/v3/files/${driveId}?alt=media`;
                    const response = await fetch(alternateUrl);
                    if (response.ok) {
                        let text = await response.text();
                        text = text.trim();
                        
                        if (isBase64(text)) {
                            try {
                                return atob(text);
                            } catch (e) {
                                console.error(`Failed to decode Base64 from alternate Google Drive API:`, e);
                            }
                        }
                        
                        return text;
                    }
                } catch (driveApiError) {
                    console.error(`Failed to fetch from Google Drive API:`, driveApiError);
                }
            }
        }
        
        console.error(`All fetch attempts failed for ${url}`);
        return null;
    }
}

function extractConfigsFromText(text) {
    const configs = [];
    const protocolPatterns = SUPPORTED_PROTOCOLS.map(protocol => ({
        protocol,
        regex: new RegExp(`(${protocol}[^\\s]+)`, 'g')
    }));

    for (const { regex } of protocolPatterns) {
        const matches = text.match(regex);
        if (matches) {
            configs.push(...matches);
        }
    }

    return configs;
}

async function extractStandardConfigs(input) {
    const configs = [];
    const lines = input.split('\n').map(line => line.trim()).filter(line => line);

    for (const line of lines) {
        if (isLink(line)) {
            const content = await fetchContent(line);
            if (content) {
                const subConfigs = await processContent(content);
                configs.push(...subConfigs);
            }
        } else if (isBase64(line)) {
            try {
                const decoded = atob(line);
                const subConfigs = await processContent(decoded);
                configs.push(...subConfigs);
            } catch (e) {
                console.error('Failed to decode Base64:', e);
            }
        } else if (isDataUriBase64(line)) {
            try {
                const base64Part = extractBase64FromDataUri(line);
                const decoded = atob(base64Part);
                const subConfigs = await processContent(decoded);
                configs.push(...subConfigs);
            } catch (e) {
                console.error('Failed to decode Base64 from data URI:', e);
            }
        } else {
            const subConfigs = extractConfigsFromText(line);
            configs.push(...subConfigs);
        }
    }

    const allText = input.replace(/\n/g, ' ');
    const subConfigsFromText = extractConfigsFromText(allText);
    configs.push(...subConfigsFromText);

    return [...new Set(configs)];
}

async function processContent(content) {
    const configs = [];
    
    if (isDataUriBase64(content)) {
        try {
            const base64Part = extractBase64FromDataUri(content);
            const decoded = atob(base64Part);
            return await processContent(decoded);
        } catch (e) {
            console.error('Failed to decode data URI:', e);
        }
    }
    
    const lines = content.split('\n').map(line => line.trim()).filter(line => line);

    for (const line of lines) {
        if (isBase64(line)) {
            try {
                const decoded = atob(line);
                const subConfigs = extractConfigsFromText(decoded);
                configs.push(...subConfigs);
            } catch (e) {
                console.error('Failed to decode nested Base64:', e);
            }
        } else if (isDataUriBase64(line)) {
            try {
                const base64Part = extractBase64FromDataUri(line);
                const decoded = atob(base64Part);
                const subConfigs = extractConfigsFromText(decoded);
                configs.push(...subConfigs);
            } catch (e) {
                console.error('Failed to decode nested data URI Base64:', e);
            }
        } else {
            const subConfigs = extractConfigsFromText(line);
            configs.push(...subConfigs);
        }
    }

    return configs;
}

function isSingboxJSON(text) {
    try {
        const json = JSON.parse(text);
        return json && typeof json === 'object' && json.outbounds && Array.isArray(json.outbounds);
    } catch (e) {
        return false;
    }
}

function convertFromJSON(jsonText) {
    const json = JSON.parse(jsonText);
    const outbounds = json.outbounds || [];
    const proxyConfigs = [];

    for (const outbound of outbounds) {
        if (outbound.type === 'vmess') {
            const vmessConfig = convertToVmess(outbound);
            if (vmessConfig) proxyConfigs.push(vmessConfig);
        } else if (outbound.type === 'vless') {
            const vlessConfig = convertToVless(outbound);
            if (vlessConfig) proxyConfigs.push(vlessConfig);
        } else if (outbound.type === 'trojan') {
            const trojanConfig = convertToTrojan(outbound);
            if (trojanConfig) proxyConfigs.push(trojanConfig);
        } else if (outbound.type === 'hysteria2') {
            const hysteria2Config = convertToHysteria2(outbound);
            if (hysteria2Config) proxyConfigs.push(hysteria2Config);
        } else if (outbound.type === 'shadowsocks') {
            const ssConfig = convertToShadowsocks(outbound);
            if (ssConfig) proxyConfigs.push(ssConfig);
        }
    }

    return proxyConfigs;
}

async function convertConfig() {
    window.vmessCount = 0;
    window.vlessCount = 0;
    window.trojanCount = 0;
    window.hysteria2Count = 0;
    window.ssCount = 0;

    let input = document.getElementById('input').value.trim();
    const errorDiv = document.getElementById('error');
    const enableCustomTag = document.getElementById('enableCustomTag').checked;
    const customTagName = document.getElementById('customTagInput').value.trim();

    if (!input) {
        errorDiv.textContent = 'Please enter proxy configurations or Sing-box JSON';
        return;
    }

    startLoading();

    try {
        if (isLink(input)) {
            const content = await fetchContent(input);
            if (content && isSingboxJSON(content)) {
                input = content;
            } else if (content) {
                input = content;
            }
        } else if (isDataUriBase64(input)) {
            try {
                const base64Part = extractBase64FromDataUri(input);
                const decoded = atob(base64Part);
                if (isSingboxJSON(decoded)) {
                    input = decoded;
                } else {
                    input = decoded;
                }
            } catch (e) {
                console.error('Failed to decode data URI:', e);
            }
        }

        if (isSingboxJSON(input)) {
            const proxyConfigs = convertFromJSON(input);
            editor.setValue(proxyConfigs.join('\n'));
            editor.clearSelection();
            errorDiv.textContent = '';
            document.getElementById('downloadButton').disabled = false;
            document.getElementById('downloadButton').textContent = 'Download TXT';
            window.lastConversionFormat = 'urls';
        } else if (isClashConfig(input)) {
            const proxyConfigs = convertFromClashConfig(input);
            if (proxyConfigs.length === 0) throw new Error('No proxy configurations found in Clash config');
            editor.setValue(proxyConfigs.join('\n'));
            editor.clearSelection();
            errorDiv.textContent = '';
            document.getElementById('downloadButton').disabled = false;
            document.getElementById('downloadButton').textContent = 'Download TXT';
            window.lastConversionFormat = 'urls';
        } else {
            const configs = await extractStandardConfigs(input);
            const outbounds = [];
            const validTags = [];

            for (const config of configs) {
                let converted;
                try {
                    if (config.startsWith('vmess://')) {
                        converted = convertVmess(config, enableCustomTag, customTagName);
                    } else if (config.startsWith('vless://')) {
                        converted = convertVless(config, enableCustomTag, customTagName);
                    } else if (config.startsWith('trojan://')) {
                        converted = convertTrojan(config, enableCustomTag, customTagName);
                    } else if (config.startsWith('hysteria2://') || config.startsWith('hy2://')) {
                        converted = convertHysteria2(config, enableCustomTag, customTagName);
                    } else if (config.startsWith('ss://')) {
                        converted = convertShadowsocks(config, enableCustomTag, customTagName);
                    }
                } catch (e) {
                    console.error(`Failed to convert config: ${config}`, e);
                    continue;
                }

                if (converted) {
                    outbounds.push(converted);
                    validTags.push(converted.tag);
                }
            }

            if (outbounds.length === 0) {
                throw new Error('No valid configurations found');
            }

            const singboxConfig = createModernSingboxConfig(outbounds, validTags);
            const jsonString = JSON.stringify(singboxConfig, null, 2);
            editor.setValue(jsonString);
            editor.clearSelection();
            errorDiv.textContent = '';
            document.getElementById('downloadButton').disabled = false;
            document.getElementById('downloadButton').textContent = 'Download JSON';
            window.lastConversionFormat = 'singbox';
        }
    } catch (error) {
        errorDiv.textContent = error.message;
        editor.setValue('');
        document.getElementById('downloadButton').disabled = true;
    } finally {
        stopLoading();
    }
}

function createModernSingboxConfig(outbounds, validTags) {
    return {
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": [
                { "type": "https", "server": "8.8.8.8", "detour": "🌐 Anonymous Multi", "tag": "dns-remote" },
                { "type": "udp", "server": "8.8.8.8", "server_port": 53, "tag": "dns-direct" },
                { "type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18" }
            ],
            "rules": [
                { "domain": ["raw.githubusercontent.com"], "server": "dns-direct" },
                { "clash_mode": "Direct", "server": "dns-direct" },
                { "clash_mode": "Global", "server": "dns-remote" },
                { "type": "logical", "mode": "and", "rules": [{ "rule_set": "geosite-ir" }, { "rule_set": "geoip-ir" }], "action": "route", "server": "dns-direct" },
                { "rule_set": ["geosite-malware", "geosite-phishing", "geosite-cryptominers", "geosite-category-ads-all"], "action": "reject" },
                { "disable_cache": true, "inbound": "tun-in", "query_type": ["A", "AAAA"], "server": "dns-fake" }
            ],
            "strategy": "ipv4_only",
            "independent_cache": true
        },
        "inbounds": [
            { "type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "mixed" },
            { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080 }
        ],
        "outbounds": [
            { "type": "selector", "tag": "🌐 Anonymous Multi", "outbounds": ["👽 Best Ping 🚀", ...validTags, "direct"] },
            { "type": "direct", "tag": "direct" },
            { "type": "urltest", "tag": "👽 Best Ping 🚀", "outbounds": validTags, "url": "https://www.gstatic.com/generate_204", "interrupt_exist_connections": false, "interval": "30s" },
            ...outbounds
        ],
        "route": {
            "rules": [
                { "action": "sniff" },
                { "protocol": "dns", "action": "hijack-dns" },
                { "clash_mode": "Direct", "outbound": "direct" },
                { "clash_mode": "Global", "outbound": "🌐 Anonymous Multi" },
                { "ip_is_private": true, "outbound": "direct" },
                { "network": "udp", "action": "reject" },
                { "rule_set": ["geosite-malware", "geosite-phishing", "geosite-cryptominers", "geosite-category-ads-all"], "action": "reject" },
                { "rule_set": ["geoip-malware", "geoip-phishing"], "action": "reject" },
                { "rule_set": ["geosite-ir"], "outbound": "direct" },
                { "rule_set": ["geoip-ir"], "outbound": "direct" }
            ],
            "rule_set": [
                { "type": "remote", "tag": "geosite-malware", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geoip-malware", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geosite-phishing", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geoip-phishing", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geosite-cryptominers", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geosite-ir", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs", "download_detour": "direct" },
                { "type": "remote", "tag": "geoip-ir", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs", "download_detour": "direct" }
            ],
            "auto_detect_interface": true,
            "default_domain_resolver": { "server": "dns-direct", "strategy": "prefer_ipv4", "rewrite_ttl": 60 },
            "final": "🌐 Anonymous Multi"
        },
        "ntp": { "enabled": true, "server": "time.cloudflare.com", "server_port": 123, "domain_resolver": "dns-direct", "interval": "30m", "write_to_system": false },
        "experimental": {
            "cache_file": { "enabled": true, "store_fakeip": true },
            "clash_api": { "external_controller": "127.0.0.1:9090", "external_ui": "ui", "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip", "external_ui_download_detour": "direct", "default_mode": "Rule" }
        }
    };
}
function isClashConfig(text) {
    try {
        const json = JSON.parse(text);
        return json && typeof json === 'object' && json.proxies && Array.isArray(json.proxies);
    } catch (e) {
        try {
            const yaml = jsyaml.load(text);
            return yaml && typeof yaml === 'object' && yaml.proxies && Array.isArray(yaml.proxies);
        } catch (e2) { return false; }
    }
}

function convertFromClashConfig(text) {
    let config;
    try { config = JSON.parse(text); } catch (e) { config = jsyaml.load(text); }
    const proxies = config.proxies || [];
    const urls = [];
    for (const proxy of proxies) {
        let url = null;
        try {
            if (proxy.type === 'vmess') url = clashVmessToUrl(proxy);
            else if (proxy.type === 'vless') url = clashVlessToUrl(proxy);
            else if (proxy.type === 'trojan') url = clashTrojanToUrl(proxy);
            else if (proxy.type === 'hysteria2') url = clashHysteria2ToUrl(proxy);
            else if (proxy.type === 'ss') url = clashSsToUrl(proxy);
        } catch (e) { continue; }
        if (url) urls.push(url);
    }
    return urls;
}

function singboxOutboundToClashProxy(outbound) {
    const { type, tag, server, server_port, transport, tls } = outbound;
    if (!type || !server || !server_port) return null;
    const base = { name: tag || type, server, port: server_port };
    const wsOpts = transport?.type === 'ws' ? {
        'ws-opts': {
            path: transport.path || '/',
            ...(transport.headers?.Host ? { headers: { Host: transport.headers.Host } } : {})
        }
    } : {};
    const tlsFields = tls?.enabled ? {
        tls: true, servername: tls.server_name || server,
        'skip-cert-verify': false,
        'client-fingerprint': tls.utls?.fingerprint || 'chrome'
    } : {};
    if (type === 'vmess') {
        return { ...base, type: 'vmess', uuid: outbound.uuid, alterId: outbound.alter_id || 0,
            cipher: outbound.security || 'auto', network: transport?.type || 'tcp', ...wsOpts, ...tlsFields };
    } else if (type === 'vless') {
        return { ...base, type: 'vless', uuid: outbound.uuid,
            network: transport?.type || 'tcp', ...wsOpts, ...tlsFields };
    } else if (type === 'trojan') {
        return { ...base, type: 'trojan', password: outbound.password,
            sni: tls?.server_name || server, 'skip-cert-verify': false,
            ...(transport?.type === 'ws' ? { network: 'ws', ...wsOpts } : {}) };
    } else if (type === 'hysteria2') {
        return { ...base, type: 'hysteria2', auth: outbound.password || '',
            sni: tls?.server_name || server, 'skip-cert-verify': tls?.insecure || false };
    } else if (type === 'shadowsocks') {
        return { ...base, type: 'ss', cipher: outbound.method, password: outbound.password };
    }
    return null;
}

function createModernClashConfig(outbounds, validTags) {
    const clashProxies = outbounds.map(o => singboxOutboundToClashProxy(o)).filter(Boolean);
    const proxyNames = clashProxies.map(p => p.name);
    return {
        'mixed-port': 7890,
        'allow-lan': false,
        'unified-delay': false,
        'log-level': 'silent',
        mode: 'rule',
        'tcp-concurrent': true,
        'geo-auto-update': true,
        'geo-update-interval': 168,
        'external-controller': '127.0.0.1:9090',
        'external-ui': 'ui',
        profile: { 'store-selected': true, 'store-fake-ip': true },
        tun: {
            enable: true, stack: 'mixed', 'auto-route': true, 'strict-route': true,
            'auto-detect-interface': true, 'dns-hijack': ['any:53', 'tcp://any:53'], mtu: 9000
        },
        sniffer: {
            enable: true, 'force-dns-mapping': true, 'parse-pure-ip': true, 'override-destination': true,
            sniff: { HTTP: { ports: [80, 8080] }, TLS: { ports: [443, 8443, 2053, 2083, 2087, 2096] } }
        },
        dns: {
            enable: true, 'respect-rules': true, 'use-system-hosts': false,
            listen: '127.0.0.1:1053', ipv6: false,
            nameserver: ['https://8.8.8.8/dns-query#✅ Anonymous Multi'],
            'proxy-server-nameserver': ['8.8.8.8#DIRECT'],
            'direct-nameserver': ['8.8.8.8#DIRECT'],
            'direct-nameserver-follow-policy': true,
            'nameserver-policy': { 'rule-set:geosite-ir': '8.8.8.8#DIRECT' },
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'fake-ip-filter-mode': 'blacklist',
            'fake-ip-filter': ['+.lan', '+.local']
        },
        proxies: clashProxies,
        'proxy-groups': [
            { name: '✅ Anonymous Multi', type: 'select', proxies: ['🚀 Best Ping', ...proxyNames, 'DIRECT'] },
            { name: '🚀 Best Ping', type: 'url-test', proxies: proxyNames, url: 'https://www.gstatic.com/generate_204', interval: 180, tolerance: 50 }
        ],
        'rule-providers': {
            'geosite-malware': { type: 'http', format: 'text', behavior: 'domain', path: './ruleset/geosite-malware.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt' },
            'geosite-phishing': { type: 'http', format: 'text', behavior: 'domain', path: './ruleset/geosite-phishing.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt' },
            'geosite-cryptominers': { type: 'http', format: 'text', behavior: 'domain', path: './ruleset/geosite-cryptominers.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.txt' },
            'geosite-ads': { type: 'http', format: 'text', behavior: 'domain', path: './ruleset/geosite-ads.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt' },
            'geosite-ir': { type: 'http', format: 'text', behavior: 'domain', path: './ruleset/geosite-ir.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt' },
            'geoip-ir': { type: 'http', format: 'text', behavior: 'ipcidr', path: './ruleset/geoip-ir.txt', interval: 86400, url: 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt' }
        },
        rules: [
            'GEOIP,lan,DIRECT,no-resolve',
            'NETWORK,udp,REJECT',
            'RULE-SET,geosite-malware,REJECT',
            'RULE-SET,geosite-phishing,REJECT',
            'RULE-SET,geosite-cryptominers,REJECT',
            'RULE-SET,geosite-ads,REJECT',
            'RULE-SET,geosite-ir,DIRECT',
            'RULE-SET,geoip-ir,DIRECT',
            'MATCH,✅ Anonymous Multi'
        ],
        ntp: { enable: true, server: 'time.cloudflare.com', port: 123, interval: 30 }
    };
}

async function convertToClash() {
    window.vmessCount = 0; window.vlessCount = 0; window.trojanCount = 0;
    window.hysteria2Count = 0; window.ssCount = 0;

    let input = document.getElementById('input').value.trim();
    const errorDiv = document.getElementById('error');
    const enableCustomTag = document.getElementById('enableCustomTag').checked;
    const customTagName = document.getElementById('customTagInput').value.trim();

    if (!input) {
        errorDiv.textContent = 'Please enter proxy configurations';
        return;
    }

    startLoading();
    try {
        if (isLink(input)) {
            const content = await fetchContent(input);
            if (content) input = content;
        } else if (isDataUriBase64(input)) {
            try { const b = extractBase64FromDataUri(input); input = atob(b); } catch (e) {}
        }

        const configs = await extractStandardConfigs(input);
        const outbounds = [], validTags = [];
        for (const config of configs) {
            let converted;
            try {
                if (config.startsWith('vmess://')) converted = convertVmess(config, enableCustomTag, customTagName);
                else if (config.startsWith('vless://')) converted = convertVless(config, enableCustomTag, customTagName);
                else if (config.startsWith('trojan://')) converted = convertTrojan(config, enableCustomTag, customTagName);
                else if (config.startsWith('hysteria2://') || config.startsWith('hy2://')) converted = convertHysteria2(config, enableCustomTag, customTagName);
                else if (config.startsWith('ss://')) converted = convertShadowsocks(config, enableCustomTag, customTagName);
            } catch (e) { continue; }
            if (converted) { outbounds.push(converted); validTags.push(converted.tag); }
        }
        if (outbounds.length === 0) throw new Error('No valid configurations found');

        const clashConfig = createModernClashConfig(outbounds, validTags);
        editor.setValue(JSON.stringify(clashConfig, null, 2));
        editor.clearSelection();
        errorDiv.textContent = '';
        document.getElementById('downloadButton').disabled = false;
        document.getElementById('downloadButton').textContent = 'Download YAML';
        window.lastConversionFormat = 'clash';
    } catch (error) {
        errorDiv.textContent = error.message;
        editor.setValue('');
        document.getElementById('downloadButton').disabled = true;
    } finally {
        stopLoading();
    }
}