// A form fixture for the browser contract shared by both framework wrappers.
const html = `<!doctype html><meta charset="utf-8"><style>body{max-width:700px;margin:30px auto;font:16px system-ui}oxidt-markdown-editor{--md-editor-min-height:10rem}</style>
<form><label for="body">Message</label><oxidt-markdown-editor><div data-editor-host></div><textarea id="body" name="body" aria-label="Message" required># Original\n\n**Text**</textarea></oxidt-markdown-editor><button>Save</button><button type="reset">Reset</button></form>
<script>window.inputs=0;window.submits=0;document.querySelector('textarea').addEventListener('input',()=>window.inputs++);document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submits++})</script>`;
Bun.serve({ hostname: '127.0.0.1', port: 4197, fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/editor.js') return new Response(Bun.file('assets/markdown-editor.js'), { headers: { 'content-type': 'text/javascript' } });
    const page = url.searchParams.has('labels') ? html.replace('<textarea id="body"', `<textarea data-labels='{"heading-1":"Überschrift 1"}' id="body"`) : html;
    return new Response(page + (url.searchParams.has('fallback') ? '' : '<script type="module" src="/editor.js"></script>'), { headers: { 'content-type': 'text/html' } });
} });
