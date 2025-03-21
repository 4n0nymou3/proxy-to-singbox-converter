function convertVmess(input) {
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
            tag: `vmess-${generateUUID().slice(0, 8)}`,
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

function convertVless(input) {
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
            tag: `vless-${generateUUID().slice(0, 8)}`,
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

function convertTrojan(input) {
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
            tag: `trojan-${generateUUID().slice(0, 8)}`,
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

function convertHysteria2(input) {
    try {
        const url = new URL(input);
        if (!['hysteria2:', 'hy2:'].includes(url.protocol.toLowerCase()) || !url.hostname || !url.port) return null;
        const params = new URLSearchParams(url.search);
        return {
            type: "hysteria2",
            tag: `hysteria2-${generateUUID().slice(0, 8)}`,
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

function convertShadowsocks(input) {
    try {
        const ss = input.replace('ss://', '');
        const [serverPart, _] = ss.split('#');
        const [methodAndPass, serverAndPort] = serverPart.split('@');
        const [method, password] = atob(methodAndPass).split(':');
        const [server, port] = serverAndPort.split(':');
        if (!server || !port) return null;
        return {
            type: "shadowsocks",
            tag: `ss-${generateUUID().slice(0, 8)}`,
            server: server,
            server_port: parseInt(port),
            method: method,
            password: password
        };
    } catch (error) {
        throw new Error('Invalid Shadowsocks configuration');
    }
}

function convertJsonToVmess(json) {
    const data = {
        v: "2",
        ps: json.tag,
        add: json.server,
        port: json.server_port,
        id: json.uuid,
        aid: json.alter_id || 0,
        scy: json.security || "auto",
        net: json.transport.type || "tcp",
        path: json.transport.path || "",
        host: json.transport.headers?.Host || "",
        tls: json.tls?.enabled ? "tls" : "",
        sni: json.tls?.server_name || ""
    };
    return "vmess://" + btoa(JSON.stringify(data));
}

function convertJsonToVless(json) {
    let url = `vless://${json.uuid}@${json.server}:${json.server_port}`;
    const params = new URLSearchParams();
    if (json.flow) params.set("flow", json.flow);
    if (json.transport.type) params.set("type", json.transport.type);
    if (json.transport.path) params.set("path", json.transport.path);
    if (json.transport.headers?.Host) params.set("host", json.transport.headers.Host);
    if (json.tls?.server_name) params.set("sni", json.tls.server_name);
    if (params.toString()) url += "?" + params.toString();
    return url;
}

function convertJsonToTrojan(json) {
    let url = `trojan://${json.password}@${json.server}:${json.server_port}`;
    const params = new URLSearchParams();
    if (json.transport.type) params.set("type", json.transport.type);
    if (json.transport.path) params.set("path", json.transport.path);
    if (json.tls?.server_name) params.set("sni", json.tls.server_name);
    if (json.tls?.alpn?.length) params.set("alpn", json.tls.alpn.join(","));
    if (params.toString()) url += "?" + params.toString();
    return url;
}

function convertJsonToHysteria2(json) {
    let url = `hysteria2://${json.password}@${json.server}:${json.server_port}`;
    const params = new URLSearchParams();
    if (json.tls?.server_name) params.set("sni", json.tls.server_name);
    if (params.toString()) url += "?" + params.toString();
    return url;
}

function convertJsonToShadowsocks(json) {
    const auth = btoa(`${json.method}:${json.password}`);
    return `ss://${auth}@${json.server}:${json.server_port}`;
}