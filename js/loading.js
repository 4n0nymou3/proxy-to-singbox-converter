function startLoading() {
    const loadingEl = document.getElementById('loading');
    const checkboxCustomTag = document.getElementById('enableCustomTag');
    const pasteButtons = document.querySelectorAll('.terminal-actions button');

    loadingEl.style.display = 'flex';
    ['toSingboxBtn', 'toClashBtn', 'extractUrlsBtn', 'clearButton'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = true;
    });
    checkboxCustomTag.disabled = true;
    pasteButtons.forEach(btn => btn.disabled = true);
}

function stopLoading() {
    const loadingEl = document.getElementById('loading');
    const checkboxCustomTag = document.getElementById('enableCustomTag');
    const pasteButtons = document.querySelectorAll('.terminal-actions button');

    loadingEl.style.display = 'none';
    checkboxCustomTag.disabled = false;
    pasteButtons.forEach(btn => btn.disabled = false);
    applyButtonStates();
}