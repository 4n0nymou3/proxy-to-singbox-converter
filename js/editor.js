function convertVmess(input, enableCustomTag, customTagName) {
    try {
        const data = JSON.parse(atob(input.replace('vmess://', '')));
        if (!data.add || !data.port || !data.id) return null;
        
        const transport = {};
        if (data.net === 'ws' || data.net === 'h2') {
            if (data.path) transport.path = data.path;
            if (data.host) transport.headers = { Host: data.host };
            transport.type = data.net;
        }
        
        return {
            type: "vmess",
            tag: generateTag('vmess', enableCustomTag, customTagName),
            server: data.add,
            server_port: parseInt(data.port),
            uuid: data.id,
            security: data.scy || "auto",
            alter_id: parseInt(data.aid || 0),
            transport: transport,
            tls: {
                enabled: data.tls === 'tls',
                insecure: true,
                server_name: data.sni || data.add
            }
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
        const port = url.port || 443;
        const params = new URLSearchParams(url.search);
        
        const transport = {};
        if (params.get('type') === 'ws') {
            if (params.get('path')) transport.path = params.get('path');
            if (params.get('host')) transport.headers = { Host: params.get('host') };
            transport.type = 'ws';
        }
        
        return {
            type: "vless",
            tag: generateTag('vless', enableCustomTag, customTagName),
            server: address,
            server_port: parseInt(port),
            uuid: url.username,
            flow: params.get('flow') || '',
            transport: transport,
            tls: {
                enabled: true,
                server_name: params.get('sni') || address,
                insecure: true
            }
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
        const type = params.get('type');
        if (type && type !== 'tcp' && params.get('path')) {
            transport.path = params.get('path');
            transport.type = type;
        }
        
        return {
            type: "trojan",
            tag: generateTag('trojan', enableCustomTag, customTagName),
            server: url.hostname,
            server_port: parseInt(url.port || 443),
            password: url.username,
            transport: transport,
            tls: {
                enabled: true,
                server_name: params.get('sni') || url.hostname,
                insecure: true,
                alpn: (params.get('alpn') || '').split(',').filter(Boolean)
            }
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
            tag: generateTag('hysteria2', enableCustomTag, customTagName),
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
            tag: generateTag('ss', enableCustomTag, customTagName),
            server: server,
            server_port: parseInt(port),
            method: method,
            password: password
        };
    } catch (error) {
        throw new Error('Invalid Shadowsocks configuration');
    }
}