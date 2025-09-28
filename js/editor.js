function convertVmess(input, enableCustomTag, customTagName) {
    try {
        const data = JSON.parse(atob(input.replace('vmess://', '')));
        if (!data.add || !data.port || !data.id) return null;
        
        const transport = {};
        if (data.net === 'ws') {
            transport.type = 'ws';
            transport.path = data.path || '/';
            transport.headers = { Host: data.host || data.add };
        }
        
        let tls = {"enabled": false};
        if (data.tls === 'tls') {
            tls = {
                "enabled": true,
                "server_name": data.sni || data.add,
                "insecure": false,
                "alpn": ["http/1.1"],
                "record_fragment": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            };
        }

        return {
            type: "vmess",
            tag: generateTag('VMess', enableCustomTag, customTagName),
            server: data.add,
            server_port: parseInt(data.port),
            uuid: data.id,
            security: data.scy || "auto",
            alter_id: parseInt(data.aid || 0),
            transport: transport,
            tls: tls
        };
    } catch (error) {
        console.error('Invalid VMess configuration:', input, error);
        return null;
    }
}

function convertVless(input, enableCustomTag, customTagName) {
    try {
        const url = new URL(input);
        if (url.protocol.toLowerCase() !== 'vless:' || !url.hostname) return null;
        
        const address = url.hostname;
        const port = parseInt(url.port || 443);
        const params = new URLSearchParams(url.search);
        
        const transport = {};
        if (params.get('type') === 'ws') {
            transport.type = 'ws';
            transport.path = params.get('path') || '/';
            transport.headers = { Host: params.get('host') || address };
        }
        
        let tls = {"enabled": false};
        const tls_enabled = params.get('security') === 'tls' || [443, 2053, 2083, 2087, 2096, 8443].includes(port);
        if (tls_enabled) {
            tls = {
                "enabled": true,
                "server_name": params.get('sni') || address,
                "insecure": false,
                "alpn": ["http/1.1"],
                "record_fragment": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            };
        }

        return {
            type: "vless",
            tag: generateTag('VLESS', enableCustomTag, customTagName),
            server: address,
            server_port: port,
            uuid: url.username,
            flow: params.get('flow') || '',
            transport: transport,
            tls: tls
        };
    } catch (error) {
        console.error('Invalid VLESS configuration:', input, error);
        return null;
    }
}

function convertTrojan(input, enableCustomTag, customTagName) {
    try {
        const url = new URL(input);
        if (url.protocol.toLowerCase() !== 'trojan:' || !url.hostname) return null;
        
        const params = new URLSearchParams(url.search);
        const transport = {};
        if (params.get('type') === 'ws') {
            transport.type = 'ws';
            transport.path = params.get('path') || '/';
            transport.headers = { Host: params.get('host') || url.hostname };
        }
        
        const tls = {
            "enabled": true,
            "server_name": params.get('sni') || url.hostname,
            "insecure": false,
            "alpn": ["http/1.1"],
            "record_fragment": false,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        };

        return {
            type: "trojan",
            tag: generateTag('Trojan', enableCustomTag, customTagName),
            server: url.hostname,
            server_port: parseInt(url.port || 443),
            password: url.username,
            transport: transport,
            tls: tls
        };
    } catch (error) {
        console.error('Invalid Trojan configuration:', input, error);
        return null;
    }
}

function convertHysteria2(input, enableCustomTag, customTagName) {
    try {
        const url = new URL(input);
        if (!['hysteria2:', 'hy2:'].includes(url.protocol.toLowerCase()) || !url.hostname || !url.port) return null;
        
        const params = new URLSearchParams(url.search);
        return {
            type: "hysteria2",
            tag: generateTag('Hysteria2', enableCustomTag, customTagName),
            server: url.hostname,
            server_port: parseInt(url.port),
            password: url.username || params.get('password') || '',
            tls: {
                enabled: true,
                server_name: params.get('sni') || url.hostname,
                insecure: true
            }
        };
    } catch (error) {
        console.error('Invalid Hysteria2 configuration:', input, error);
        return null;
    }
}

function convertShadowsocks(input, enableCustomTag, customTagName) {
    try {
        const url = new URL(input);
        if (url.protocol.toLowerCase() !== 'ss:') return null;

        const server = url.hostname;
        const port = parseInt(url.port);
        
        if (!server || !port || isNaN(port)) {
            console.error('Invalid SS config: Missing server or port.');
            return null;
        }

        let decodedUserInfo;
        try {
            decodedUserInfo = atob(url.username);
        } catch (e) {
            console.error('Invalid SS config: Could not decode base64 user info.');
            return null;
        }
        
        const userInfoParts = decodedUserInfo.split(':');
        if (userInfoParts.length !== 2) {
            console.error('Invalid SS config: Decoded user info is not in "method:password" format.');
            return null;
        }
        
        const method = userInfoParts[0];
        const password = userInfoParts[1];
        
        if (!method || !password) {
            console.error('Invalid SS config: Missing method or password after decoding.');
            return null;
        }

        return {
            type: "shadowsocks",
            tag: generateTag('SS', enableCustomTag, customTagName),
            server: server,
            server_port: port,
            method: method,
            password: password
        };
    } catch (error) {
        console.error('Invalid Shadowsocks configuration:', input, error);
        return null;
    }
}