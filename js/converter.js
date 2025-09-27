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
    const enableAdBlockAndIran = document.getElementById('enableAdBlockAndIran').checked;
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

            const singboxConfig = enableAdBlockAndIran ? createEnhancedSingboxConfig(outbounds, validTags) : createSingboxConfig(outbounds, validTags);
            const jsonString = JSON.stringify(singboxConfig, null, 2);
            editor.setValue(jsonString);
            editor.clearSelection();
            errorDiv.textContent = '';
            document.getElementById('downloadButton').disabled = false;
        }
    } catch (error) {
        errorDiv.textContent = error.message;
        editor.setValue('');
        document.getElementById('downloadButton').disabled = true;
    } finally {
        stopLoading();
    }
}

function createSingboxConfig(outbounds, validTags) {
    return {
        dns: {
            final: "local-dns",
            rules: [
                { clash_mode: "Global", server: "proxy-dns", source_ip_cidr: ["172.19.0.0/30"] },
                { server: "proxy-dns", source_ip_cidr: ["172.19.0.0/30"] },
                { clash_mode: "Direct", server: "direct-dns" }
            ],
            servers: [
                {
                    address: "tls://208.67.222.123",
                    address_resolver: "local-dns",
                    detour: "proxy",
                    tag: "proxy-dns"
                },
                {
                    address: "local",
                    detour: "direct",
                    tag: "local-dns"
                },
                {
                    address: "rcode://success",
                    tag: "block"
                },
                {
                    address: "local",
                    detour: "direct",
                    tag: "direct-dns"
                }
            ],
            strategy: "prefer_ipv4"
        },
        inbounds: [
            {
                address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                auto_route: true,
                endpoint_independent_nat: false,
                mtu: 9000,
                platform: {
                    http_proxy: {
                        enabled: true,
                        server: "127.0.0.1",
                        server_port: 2080
                    }
                },
                sniff: true,
                stack: "system",
                strict_route: false,
                type: "tun"
            },
            {
                listen: "127.0.0.1",
                listen_port: 2080,
                sniff: true,
                type: "mixed",
                users: []
            }
        ],
        outbounds: [
            {
                tag: "proxy",
                type: "selector",
                outbounds: ["auto"].concat(validTags).concat(["direct"])
            },
            {
                tag: "auto",
                type: "urltest",
                outbounds: validTags,
                url: "http://www.gstatic.com/generate_204",
                interval: "10m",
                tolerance: 50
            },
            {
                tag: "direct",
                type: "direct"
            },
            ...outbounds
        ],
        route: {
            auto_detect_interface: true,
            final: "proxy",
            rules: [
                { clash_mode: "Direct", outbound: "direct" },
                { clash_mode: "Global", outbound: "proxy" },
                { protocol: "dns", action: "hijack-dns" }
            ]
        }
    };
}

function createEnhancedSingboxConfig(outbounds, validTags) {
    return {
        dns: {
            final: "local-dns",
            rules: [
                { clash_mode: "Global", server: "proxy-dns", source_ip_cidr: ["172.19.0.0/30"] },
                { server: "proxy-dns", source_ip_cidr: ["172.19.0.0/30"] },
                { clash_mode: "Direct", server: "direct-dns" },
                {
                    rule_set: ["geosite-ir"],
                    server: "direct-dns"
                },
                {
                    rule_set: ["geosite-category-ads-all", "geosite-malware", "geosite-phishing", "geosite-cryptominers"],
                    server: "block"
                }
            ],
            servers: [
                {
                    address: "tls://208.67.222.123",
                    address_resolver: "local-dns",
                    detour: "proxy",
                    tag: "proxy-dns"
                },
                {
                    address: "local",
                    detour: "direct",
                    tag: "local-dns"
                },
                {
                    address: "rcode://success",
                    tag: "block"
                },
                {
                    address: "local",
                    detour: "direct",
                    tag: "direct-dns"
                }
            ],
            strategy: "prefer_ipv4"
        },
        inbounds: [
            {
                address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                auto_route: true,
                endpoint_independent_nat: false,
                mtu: 9000,
                platform: {
                    http_proxy: {
                        enabled: true,
                        server: "127.0.0.1",
                        server_port: 2080
                    }
                },
                sniff: true,
                stack: "system",
                strict_route: false,
                type: "tun"
            },
            {
                listen: "127.0.0.1",
                listen_port: 2080,
                sniff: true,
                type: "mixed",
                users: []
            }
        ],
        outbounds: [
            {
                tag: "proxy",
                type: "selector",
                outbounds: ["auto"].concat(validTags).concat(["direct"])
            },
            {
                tag: "auto",
                type: "urltest",
                outbounds: validTags,
                url: "http://www.gstatic.com/generate_204",
                interval: "10m",
                tolerance: 50
            },
            {
                tag: "direct",
                type: "direct"
            },
            ...outbounds
        ],
        route: {
            auto_detect_interface: true,
            final: "proxy",
            rules: [
                { clash_mode: "Direct", outbound: "direct" },
                { clash_mode: "Global", outbound: "proxy" },
                { protocol: "dns", action: "hijack-dns" },
                {
                    domain_suffix: [".ir"],
                    outbound: "direct"
                },
                {
                    rule_set: ["geoip-ir", "geosite-ir"],
                    outbound: "direct"
                },
                {
                    rule_set: ["geosite-category-ads-all", "geosite-malware", "geosite-phishing", "geosite-cryptominers", "geoip-malware", "geoip-phishing"],
                    outbound: "block"
                }
            ],
            rule_set: [
                {
                    tag: "geosite-ir",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geosite-category-ads-all",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geosite-malware",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geosite-phishing",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geosite-cryptominers",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geoip-ir",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geoip-malware",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                },
                {
                    tag: "geoip-phishing",
                    type: "remote",
                    format: "binary",
                    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs",
                    download_detour: "direct",
                    update_interval: "1d"
                }
            ]
        }
    };
}