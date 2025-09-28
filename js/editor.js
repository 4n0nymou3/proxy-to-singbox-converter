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
        throw new Error('Invalid VMess configuration');
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
        throw new Error('Invalid VLESS configuration');
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
        throw new Error('Invalid Trojan configuration');
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
        throw new Error('Invalid Hysteria2 configuration');
    }
}

function convertShadowsocks(input, enableCustomTag, customTagName) {
    try {
        const ss = input.replace('ss://', '');
        const [serverPart, _] = ss.split('#');
        const [methodAndPass, serverAndPort] = serverPart.split('@');
        const [method, password] = atob(methodAndPass).split(':');
        const [server, port] = serverAndPort.split(':');
        
        if (!server || !port) return null;
        
        return {
            type: "shadowsocks",
            tag: generateTag('SS', enableCustomTag, customTagName),
            server: server,
            server_port: parseInt(port),
            method: method,
            password: password
        };
    } catch (error) {
        throw new Error('Invalid Shadowsocks configuration');
    }
}