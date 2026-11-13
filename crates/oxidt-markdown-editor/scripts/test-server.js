// A form fixture for the browser contract shared by both framework wrappers.
const html = `<!doctype html><meta charset="utf-8"><style>body{max-width:700px;margin:30px auto;font:16px system-ui}oxidt-markdown-editor{--md-editor-min-height:10rem}</style>
<form><label for="body">Message</label><oxidt-markdown-editor><div data-editor-host></div><textarea id="body" name="body" aria-label="Message" required># Original\n\n**Text**</textarea></oxidt-markdown-editor><button>Save</button><button type="reset">Reset</button></form>
<script>window.inputs=0;window.submits=0;document.querySelector('textarea').addEventListener('input',()=>window.inputs++);document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submits++})</script>`;
const wikiHost = `<script>
window.titles = { p1: 'Plan', p2: 'Brief' }; window.links = []; window.asked = [];
const body = document.querySelector('textarea');
body.addEventListener('markdown-complete', event => {
    event.preventDefault();
    const q = event.detail.query.toLowerCase();
    setTimeout(() => event.detail.respond(Object.entries(window.titles).filter(([, t]) => t.toLowerCase().includes(q))
        .map(([id, title]) => ({ label: title, detail: 'Page', insert: '[[' + id + ']]' }))), 20);
});
body.addEventListener('markdown-resolve', event => {
    event.preventDefault();
    window.asked.push(event.detail.targets);
    setTimeout(() => event.detail.respond(Object.fromEntries(event.detail.targets.map(t =>
        [t, window.titles[t] ? { title: window.titles[t], href: '/p/' + t } : null]))), 20);
});
body.addEventListener('markdown-link', event => { event.preventDefault(); window.links.push(event.detail); });
</script>`;
Bun.serve({ hostname: '127.0.0.1', port: 4197, fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/editor.js') return new Response(Bun.file('assets/markdown-editor.js'), { headers: { 'content-type': 'text/javascript' } });
    let page = url.searchParams.has('labels') ? html.replace('<textarea id="body"', `<textarea data-labels='{"heading-1":"Überschrift 1"}' id="body"`) : html;
    // Host hooks: `[[` completions, link resolution, link events (`window.links`).
    if (url.searchParams.has('wiki')) page = page
        .replace('<textarea id="body"', `<textarea data-wiki-links data-completion-triggers='["[["]'${url.searchParams.has('readonly') ? ' readonly' : ''} id="body"`)
        .replace('# Original\n\n**Text**', 'See [[p1]] and [[gone]].') + wikiHost;
    return new Response(page + (url.searchParams.has('fallback') ? '' : '<script type="module" src="/editor.js"></script>'), { headers: { 'content-type': 'text/html' } });
} });
