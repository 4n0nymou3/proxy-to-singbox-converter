function startLoading() {
    const loadingEl = document.getElementById('loading');
    const convertButton = document.querySelector('button[onclick="convertConfig()"]');
    const clearButton = document.getElementById('clearButton');
    const checkboxCustomTag = document.getElementById('enableCustomTag');
    const pasteButtons = document.querySelectorAll('.terminal-actions button');

    loadingEl.style.display = 'flex';
    convertButton.disabled = true;
    clearButton.disabled = true;
    checkboxCustomTag.disabled = true;
    pasteButtons.forEach(btn => btn.disabled = true);
}

function stopLoading() {
    const loadingEl = document.getElementById('loading');
    const convertButton = document.querySelector('button[onclick="convertConfig()"]');
    const clearButton = document.getElementById('clearButton');
    const checkboxCustomTag = document.getElementById('enableCustomTag');
    const pasteButtons = document.querySelectorAll('.terminal-actions button');

    loadingEl.style.display = 'none';
    convertButton.disabled = false;
    clearButton.disabled = false;
    checkboxCustomTag.disabled = false;
    pasteButtons.forEach(btn => btn.disabled = false);
}