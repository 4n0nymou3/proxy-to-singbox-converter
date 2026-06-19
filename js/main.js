let editor;
window.lastConversionFormat = null;
window.detectedInputType = 'unknown';

document.addEventListener('DOMContentLoaded', () => {
    editor = ace.edit("editor");
    editor.setTheme("ace/theme/monokai");
    editor.session.setMode("ace/mode/json");
    editor.setReadOnly(true);
    editor.setOption("wrap", true);
    editor.setShowPrintMargin(false);

    const input = document.getElementById('input');
    input.addEventListener('input', checkInputType);

    checkInputType();
});

function applyButtonStates() {
    const input = document.getElementById('input').value.trim();
    const toSingboxBtn = document.getElementById('toSingboxBtn');
    const toClashBtn = document.getElementById('toClashBtn');
    const extractUrlsBtn = document.getElementById('extractUrlsBtn');
    const clearButton = document.getElementById('clearButton');
    const downloadButton = document.getElementById('downloadButton');

    clearButton.disabled = !input;

    if (!input) {
        downloadButton.disabled = true;
        toSingboxBtn.disabled = true;
        toClashBtn.disabled = true;
        extractUrlsBtn.disabled = true;
        return;
    }

    if (window.detectedInputType === 'singbox') {
        toSingboxBtn.disabled = true;
        toClashBtn.disabled = false;
        extractUrlsBtn.disabled = false;
    } else if (window.detectedInputType === 'clash') {
        toSingboxBtn.disabled = false;
        toClashBtn.disabled = true;
        extractUrlsBtn.disabled = false;
    } else {
        toSingboxBtn.disabled = false;
        toClashBtn.disabled = false;
        extractUrlsBtn.disabled = true;
    }
}

async function checkInputType() {
    const input = document.getElementById('input').value.trim();

    if (!input) {
        window.detectedInputType = 'unknown';
        applyButtonStates();
        return;
    }

    let content = input;

    if (isLink(input)) {
        window.detectedInputType = 'urls';
        applyButtonStates();
        try {
            const fetched = await fetchContent(input);
            if (fetched) content = fetched;
        } catch (e) {}
    } else if (isDataUriBase64(input)) {
        try { content = atob(extractBase64FromDataUri(input)); } catch(e) {}
    } else if (isBase64(input)) {
        try { content = atob(input); } catch(e) {}
    }

    if (isSingboxJSON(content)) {
        window.detectedInputType = 'singbox';
    } else if (isClashConfig(content)) {
        window.detectedInputType = 'clash';
    } else {
        window.detectedInputType = 'urls';
    }

    applyButtonStates();
}

function clearAll() {
    document.getElementById('input').value = '';
    editor.setValue('');
    document.getElementById('error').textContent = '';
    document.getElementById('downloadButton').disabled = true;
    document.getElementById('downloadButton').textContent = 'Download JSON';
    window.lastConversionFormat = null;
    window.detectedInputType = 'unknown';
    applyButtonStates();
}

function copyToClipboard() {
    const content = editor.getValue();
    if (!content) return;
    navigator.clipboard.writeText(content)
        .then(() => alert('Configuration copied to clipboard!'))
        .catch(err => console.error('Failed to copy:', err));
}

function copySubscriptionLink() {
    const link = document.querySelector('.subscription-input').value;
    navigator.clipboard.writeText(link)
        .then(() => alert('Subscription link copied to clipboard!'))
        .catch(err => console.error('Failed to copy:', err));
}

function downloadJSON() {
    const content = editor.getValue();
    if (!content) return;
    let fileType = 'json';
    if (window.lastConversionFormat === 'clash') fileType = 'yaml';
    else if (window.lastConversionFormat === 'urls') fileType = 'txt';
    const mime = fileType === 'json' ? 'application/json' : fileType === 'yaml' ? 'text/yaml' : 'text/plain';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `config.${fileType}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function pasteFromClipboard() {
    try {
        navigator.clipboard.readText()
            .then(text => {
                document.getElementById('input').value = text;
                checkInputType();
            })
            .catch(err => {
                alert('Please allow clipboard access to paste content');
                console.error('Failed to paste:', err);
            });
    }
    catch {
        alert('Please allow clipboard access to paste content');
    }
}

async function pasteFromURL() {
    const url = prompt('Enter URL:');
    if (!url) return;

    try {
        startLoading();
        const content = await fetchContent(url);
        if (content) {
            document.getElementById('input').value = content;
            await checkInputType();
        } else {
            throw new Error('Failed to fetch content from URL');
        }
    } catch (err) {
        alert('Failed to fetch from URL: ' + err.message);
        console.error('Failed to fetch:', err);
    } finally {
        stopLoading();
    }
}

function pasteFromFile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt,.json,.yaml,.yml,.conf,.vless,.vmess,.trojan,.hysteria,.ss,.ssr,.vlessconf,.vmessconf,.trojanconf,.hysteriaconf,.ssconf,.ssrconf';

    input.onchange = function(e) {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('input').value = e.target.result;
            checkInputType();
        };
        reader.onerror = function(e) {
            alert('Error reading file');
            console.error('File read error:', e);
        };
        reader.readAsText(file);
    };

    input.click();
}

function toggleCustomTagInput() {
    const checkbox = document.getElementById('enableCustomTag');
    const input = document.getElementById('customTagInput');
    input.disabled = !checkbox.checked;
}