import { Compartment, EditorState, Prec, StateEffect, StateField } from "@codemirror/state";
import { Decoration, EditorView, ViewPlugin, WidgetType, keymap, placeholder } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, isolateHistory } from "@codemirror/commands";
import { Language, LanguageSupport, syntaxTree } from "@codemirror/language";
import { commonmarkLanguage, markdownKeymap } from "@codemirror/lang-markdown";
import { Strikethrough, Table, TaskList } from "@lezer/markdown";
import { autocompletion } from "@codemirror/autocomplete";
import { slashCommands } from "./slash-commands.js";
import { PeleError, render as renderDiagram } from "pele";

function diagramSource(state, node) {
    const info = node.getChild("CodeInfo");
    if (!info || state.sliceDoc(info.from, info.to).trim() !== "mermaid" || node.getChildren("CodeMark").length !== 2) return null;
    return node.getChildren("CodeText").map(text => state.sliceDoc(text.from, text.to)).join("");
}

let diagramId = 0;
class DiagramWidget extends WidgetType {
    constructor(source) { super(); this.source = source; }
    eq(other) { return other.source === this.source; }
    toDOM(view) {
        const diagram = document.createElement("div");
        diagram.className = "md-diagram";
        diagram.title = "Click to edit diagram";
        try {
            diagram.innerHTML = renderDiagram(this.source, {
                fontFamily: getComputedStyle(view.dom).fontFamily,
                idPrefix: "md-diagram-" + ++diagramId,
                links: false,
                images: false,
            }).svg;
        } catch (error) {
            if (!(error instanceof PeleError)) throw error;
            const message = document.createElement("div");
            message.className = "md-diagram-error";
            message.textContent = "Diagram: " + error.message;
            const source = document.createElement("pre");
            source.textContent = this.source;
            diagram.append(message, source);
        }
        diagram.addEventListener("mousedown", event => {
            event.preventDefault();
            const from = view.posAtDOM(diagram);
            view.dispatch({ selection: { anchor: from } });
            view.focus();
        });
        return diagram;
    }
    ignoreEvent() { return true; }
}

class Bullet extends WidgetType {
    toDOM() {
        const span = document.createElement("span");
        span.className = "md-bullet";
        span.textContent = "•";
        return span;
    }
    eq() { return true; }
    ignoreEvent() { return false; }
}

class ImageWidget extends WidgetType {
    constructor(src, alt) { super(); this.src = src; this.alt = alt; }
    eq(other) { return other.src === this.src && other.alt === this.alt; }
    toDOM() {
        const img = document.createElement("img");
        img.className = "md-image";
        img.src = this.src;
        img.alt = this.alt;
        return img;
    }
    ignoreEvent() { return false; }
}

// Cells show their source text; inline formatting inside a cell is not rendered.
class TableWidget extends WidgetType {
    constructor(rows, source) { super(); this.rows = rows; this.source = source; }
    eq(other) { return other.source === this.source; }
    toDOM(view) {
        const table = document.createElement("table");
        table.className = "md-table";
        this.rows.forEach((cells, index) => {
            const row = table.insertRow();
            for (const text of cells) {
                const cell = document.createElement(index === 0 ? "th" : "td");
                cell.textContent = text;
                row.append(cell);
            }
        });
        // Clicking the table moves the cursor into it, which reveals the source.
        table.addEventListener("mousedown", event => {
            event.preventDefault();
            const from = view.posAtDOM(table);
            view.dispatch({ selection: { anchor: from } });
            view.focus();
        });
        return table;
    }
    ignoreEvent() { return true; }
}

function activeLines(state, focused) {
    return focused ? state.selection.ranges.map(range => ({
        from: state.doc.lineAt(range.from).from,
        to: state.doc.lineAt(range.to).to,
    })) : [];
}

// Decorations only change presentation. The document, clipboard, undo history,
// and form value always contain the original Markdown.
export function decorations(state, focused, ranges = [{ from: 0, to: state.doc.length }]) {
    const result = [];
    const active = activeLines(state, focused);
    const editing = (from, to) => active.some(range => from <= range.to && to >= range.from);
    const mark = (from, to, className) => {
        if (from < to) result.push(Decoration.mark({ class: className }).range(from, to));
    };
    const hide = (from, to) => {
        // View plugins cannot replace line breaks. Multiline syntax remains
        // editable, with only the characters on inactive lines hidden.
        for (let pos = from; pos < to;) {
            const line = state.doc.lineAt(pos);
            const end = Math.min(line.to, to);
            if (pos < end && !editing(pos, end)) result.push(Decoration.replace({}).range(pos, end));
            pos = line.to + 1;
        }
    };
    const lineClasses = new Map();
    const lines = (from, to, className) => {
        for (let pos = state.doc.lineAt(from).from; pos <= to;) {
            const classes = lineClasses.get(pos) || new Set();
            classes.add(className);
            lineClasses.set(pos, classes);
            pos = state.doc.lineAt(pos).to + 1;
        }
    };
    // The syntax tree handles escapes, nested emphasis, and code correctly;
    // regexes over the document would also format Markdown inside code fences.
    const visited = new Set();
    const opaque = new Set(["Image", "HTMLBlock", "HTMLTag", "InlineCode", "FencedCode", "CodeBlock"]);
    for (const range of ranges) syntaxTree(state).iterate({
        from: range.from, to: range.to,
        enter(ref) {
            const { node, name, from, to } = ref;
            const id = name + ":" + from;
            // A node spanning several ranges is decorated once, but its
            // children in later ranges still need a visit.
            if (visited.has(id)) return opaque.has(name) ? false : undefined;
            visited.add(id);
            if (name === "Image") {
                const url = node.getChild("URL");
                const close = node.getChildren("LinkMark").find(mark => state.sliceDoc(mark.from, mark.to) === "]");
                if (url && close && !editing(from, to)) {
                    const alt = state.sliceDoc(from + 2, close.from);
                    result.push(Decoration.replace({ widget: new ImageWidget(state.sliceDoc(url.from, url.to), alt) }).range(from, to));
                }
                return false;
            }
            if (name === "HTMLBlock" || name === "HTMLTag" || name === "Table") return false;
            if (/^ATXHeading[1-6]$/.test(name)) {
                lines(from, to, "md-h" + name.slice(-1));
                const opening = node.firstChild;
                hide(opening.from, Math.min(opening.to + 1, to));
                const closing = node.lastChild;
                if (closing.from !== opening.from && closing.name === "HeaderMark") hide(closing.from, closing.to);
            } else if (name === "StrongEmphasis" || name === "Emphasis" || name === "Strikethrough" || name === "InlineCode") {
                mark(from, to, { StrongEmphasis: "md-strong", Emphasis: "md-em", Strikethrough: "md-strike", InlineCode: "md-inline-code" }[name]);
                hide(node.firstChild.from, node.firstChild.to);
                hide(node.lastChild.from, node.lastChild.to);
                if (name === "InlineCode") return false;
            } else if (name === "Link") {
                mark(from, to, "md-link");
                if (!editing(from, to)) {
                    hide(from, from + 1);
                    for (let child = node.firstChild?.nextSibling; child; child = child.nextSibling) {
                        if (child.name === "LinkMark" && state.sliceDoc(child.from, child.to) === "]") {
                            hide(child.from, to);
                            break;
                        }
                    }
                }
            } else if (name === "ListMark") {
                if (node.parent?.parent?.name === "BulletList" && !editing(from, to)) {
                    result.push(Decoration.replace({ widget: new Bullet() }).range(from, to));
                }
            } else if (name === "FencedCode" || name === "CodeBlock") {
                lines(from, to, "md-code-line");
                if (name === "FencedCode" && diagramSource(state, node) !== null && editing(from, to)) return false;
                for (let child = node.firstChild; child; child = child.nextSibling) {
                    if (child.name === "CodeMark" || child.name === "CodeInfo") hide(child.from, child.to);
                }
                return false;
            }
        },
    });
    for (const [pos, classes] of lineClasses) {
        result.push(Decoration.line({ class: [...classes].join(" ") }).range(pos));
    }
    return Decoration.set(result, true);
}

// Block widgets may span line breaks, which view plugins cannot replace, so
// tables and diagrams come from a state field. Focus is mirrored into state.
const setFocus = StateEffect.define();
const focusState = StateField.define({
    create: () => false,
    update(value, transaction) {
        for (const effect of transaction.effects) if (effect.is(setFocus)) value = effect.value;
        return value;
    },
});

export function blocks(state, focused) {
    const result = [];
    const active = activeLines(state, focused);
    syntaxTree(state).iterate({
        enter({ node, name, from, to }) {
            if (name !== "Table" && name !== "FencedCode") return;
            const source = name === "FencedCode" ? diagramSource(state, node) : null;
            if (name === "FencedCode" && source === null) return false;
            const start = state.doc.lineAt(from).from;
            const end = state.doc.lineAt(state.sliceDoc(to - 1, to) === "\n" ? to - 1 : to).to;
            if (active.some(range => start <= range.to && end >= range.from)) return false;
            if (source !== null) {
                result.push(Decoration.replace({ widget: new DiagramWidget(source), block: true }).range(start, end));
                return false;
            }
            const rows = [];
            for (let row = node.firstChild; row; row = row.nextSibling) {
                if (row.name !== "TableHeader" && row.name !== "TableRow") continue;
                rows.push(row.getChildren("TableCell").map(cell => state.sliceDoc(cell.from, cell.to).trim()));
            }
            result.push(Decoration.replace({ widget: new TableWidget(rows, state.sliceDoc(start, end)), block: true }).range(start, end));
            return false;
        },
    });
    return Decoration.set(result);
}

const blockPreview = StateField.define({
    create: state => blocks(state, false),
    update(value, transaction) {
        const focused = transaction.state.field(focusState);
        if (transaction.docChanged || transaction.selection || focused !== transaction.startState.field(focusState) ||
            syntaxTree(transaction.startState) !== syntaxTree(transaction.state)) {
            return blocks(transaction.state, focused);
        }
        return value;
    },
    provide: field => EditorView.decorations.from(field),
});

const livePreview = ViewPlugin.fromClass(class {
    constructor(view) { this.decorations = decorations(view.state, view.hasFocus, view.visibleRanges); }
    update(update) {
        if (update.docChanged || update.selectionSet || update.viewportChanged || update.focusChanged ||
            syntaxTree(update.startState) !== syntaxTree(update.state)) {
            this.decorations = decorations(update.state, update.view.hasFocus, update.view.visibleRanges);
        }
    }
}, { decorations: plugin => plugin.decorations });

const theme = EditorView.theme({
    "&": { backgroundColor: "var(--md-editor-background, var(--color-base-100, #fff))", color: "var(--md-editor-color, var(--color-base-content, #202936))", border: "1px solid var(--md-editor-border, var(--color-base-300, #d1d5db))", borderRadius: "0.75rem" },
    "&.cm-focused": { outline: "2px solid var(--md-editor-accent, var(--color-primary, #146ade))", outlineOffset: "2px" },
    ".cm-scroller": { fontFamily: "inherit", lineHeight: "1.75", overflowX: "auto" },
    ".cm-content": { padding: "1rem", minHeight: "var(--md-editor-min-height, 20rem)", caretColor: "var(--md-editor-color, var(--color-base-content, #202936))" },
    ".cm-line": { padding: "0" },
    ".cm-cursor": { borderLeftColor: "var(--md-editor-color, var(--color-base-content, #202936))" },
    ".cm-placeholder": { color: "color-mix(in srgb, var(--md-editor-color, var(--color-base-content, #202936)) 45%, transparent)" },
    ".md-h1": { fontSize: "2em", fontWeight: "700", lineHeight: "1.4" },
    ".md-h2": { fontSize: "1.6em", fontWeight: "700", lineHeight: "1.45" },
    ".md-h3": { fontSize: "1.3em", fontWeight: "650" },
    ".md-h4, .md-h5, .md-h6": { fontWeight: "650" },
    ".md-strong": { fontWeight: "700" },
    ".md-em": { fontStyle: "italic" },
    ".md-strike": { textDecoration: "line-through" },
    ".md-link": { color: "var(--md-editor-accent, var(--color-primary, #146ade))", textDecoration: "underline", textUnderlineOffset: "3px" },
    ".md-inline-code, .md-code-line": { fontFamily: "ui-monospace, monospace", backgroundColor: "var(--md-editor-code-background, var(--color-base-200, #f1f3f5))", fontSize: "0.9em" },
    ".md-inline-code": { borderRadius: "0.25rem" },
    ".md-code-line": { padding: "0 0.5rem" },
    ".md-image": { maxWidth: "100%", maxHeight: "20rem", verticalAlign: "middle", borderRadius: "0.5rem" },
    ".md-table": { borderCollapse: "collapse", margin: "0.25rem 0", cursor: "text" },
    ".md-table th, .md-table td": { border: "1px solid var(--md-editor-border, var(--color-base-300, #d1d5db))", padding: "0.25rem 0.65rem", textAlign: "left" },
    ".md-table th": { fontWeight: "650", backgroundColor: "var(--md-editor-code-background, var(--color-base-200, #f1f3f5))" },
    ".md-diagram": {
        margin: "0.5rem 0", cursor: "text", overflowX: "auto",
        "--pele-bg": "var(--md-editor-background, var(--color-base-100, #fff))",
        "--pele-fg": "var(--md-editor-color, var(--color-base-content, #202936))",
        "--pele-muted": "var(--pele-fg)",
        "--pele-line": "var(--pele-fg)",
        "--pele-surface": "var(--md-editor-code-background, var(--color-base-200, #f1f3f5))",
        "--pele-surface-alt": "var(--pele-surface)",
        "--pele-border": "var(--md-editor-border, var(--color-base-300, #d1d5db))",
        "--pele-accent": "var(--md-editor-accent, var(--color-primary, #146ade))",
    },
    ".md-diagram svg": { display: "block", maxWidth: "100%", height: "auto" },
    ".md-diagram pre": { whiteSpace: "pre-wrap", fontFamily: "ui-monospace, monospace" },
    ".md-diagram-error": { color: "var(--color-error, #b42318)" },
    ".md-bullet": { display: "inline-block", width: "0.7em", textAlign: "center", color: "var(--md-editor-accent, var(--color-primary, #146ade))" },
    ".cm-tooltip-autocomplete": { fontFamily: "inherit", backgroundColor: "var(--md-editor-background, var(--color-base-100, #fff))", color: "var(--md-editor-color, var(--color-base-content, #202936))", border: "1px solid var(--md-editor-border, var(--color-base-300, #d1d5db))", borderRadius: "0.5rem", overflow: "hidden", boxShadow: "0 4px 16px #0002" },
    ".cm-tooltip.cm-tooltip-autocomplete > ul": { fontFamily: "inherit", maxHeight: "min(20rem, 50vh)" },
    ".cm-tooltip.cm-tooltip-autocomplete > ul > li": { padding: "0.35rem 0.65rem", lineHeight: "1.5" },
    ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--md-editor-code-background, var(--color-base-200, #f1f3f5))", color: "var(--md-editor-color, var(--color-base-content, #202936))" },
    ".cm-completionDetail": { fontStyle: "normal", opacity: "0.65", marginLeft: "1rem" },
});

export function mountEditor(textarea, host) {
    const native = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
    const controls = new Compartment();
    let notifying = true;
    // :disabled also covers a disabled ancestor fieldset.
    const locked = () => textarea.matches(":disabled") || textarea.readOnly;
    const labels = [...textarea.labels];
    // The textarea is hidden from assistive technology, so the visible
    // textbox carries its name, requirement, and error state.
    const controlled = () => {
        const attributes = {
            "aria-label": textarea.getAttribute("aria-label") || labels[0]?.textContent.trim() || "Markdown",
            "aria-multiline": "true",
            spellcheck: "true",
        };
        for (const name of ["aria-labelledby", "aria-describedby", "aria-invalid"]) {
            if (textarea.hasAttribute(name)) attributes[name] = textarea.getAttribute(name);
        }
        if (textarea.required) attributes["aria-required"] = "true";
        return [
            EditorState.readOnly.of(locked()), EditorView.editable.of(!locked()),
            placeholder(textarea.placeholder), EditorView.contentAttributes.of(attributes),
        ];
    };
    const view = new EditorView({
        parent: host,
        doc: textarea.value,
        selection: { anchor: textarea.selectionStart, head: textarea.selectionEnd },
        extensions: [
            // markdown() would also bundle lang-html, css and javascript for
            // features this editor leaves off; only its list keymap is kept.
            new LanguageSupport(new Language(commonmarkLanguage.data, commonmarkLanguage.parser.configure([Strikethrough, Table, TaskList]), [], "markdown")),
            Prec.high(keymap.of(markdownKeymap)),
            history(), keymap.of([...defaultKeymap, ...historyKeymap]), controls.of(controlled()),
            autocompletion({ override: [slashCommands], icons: false, activateOnTypingDelay: 0, interactionDelay: 0 }),
            EditorView.lineWrapping, theme, livePreview, focusState, blockPreview,
            EditorView.focusChangeEffect.of((_, focusing) => setFocus.of(focusing)),
            EditorState.transactionFilter.of(transaction => {
                const limit = textarea.maxLength;
                return transaction.isUserEvent("input") && limit >= 0 && transaction.newDoc.length > limit &&
                    transaction.newDoc.length > transaction.startState.doc.length ? [] : transaction;
            }),
            EditorView.updateListener.of(update => {
                const selection = update.state.selection.main;
                if (update.docChanged) native.set.call(textarea, update.state.doc.toString());
                textarea.setSelectionRange(selection.from, selection.to);
                if (update.docChanged && notifying) textarea.dispatchEvent(new Event("input", { bubbles: true }));
            }),
        ],
    });
    const hadFocus = document.activeElement === textarea;
    const wasHidden = textarea.hidden;
    host.hidden = wasHidden;
    textarea.hidden = true;
    if (hadFocus) view.focus();
    const observer = new MutationObserver(records => {
        if (records.some(record => record.target === textarea || record.target.localName === "fieldset")) {
            view.dispatch({ effects: controls.reconfigure(controlled()) });
        }
    });
    observer.observe(textarea, { attributes: true, attributeFilter: ["disabled", "readonly", "placeholder", "required", "aria-label", "aria-labelledby", "aria-describedby", "aria-invalid"] });
    // Any fieldset may come to contain the field, so watch them page-wide.
    observer.observe(document, { attributes: true, attributeFilter: ["disabled"], subtree: true });
    const focus = event => { event.preventDefault(); view.focus(); };
    textarea.addEventListener("invalid", focus);
    labels.forEach(label => label.addEventListener("click", focus));
    const api = {
        setValue(value, notify = true) {
            notifying = notify;
            try {
                if (value !== view.state.doc.toString()) view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value }, annotations: isolateHistory.of("full") });
            } finally { notifying = true; }
        },
        insert(at, text) {
            if (locked()) return false;
            const before = view.state.doc;
            view.dispatch({ changes: { from: at, insert: text }, selection: { anchor: at + text.length }, scrollIntoView: true, userEvent: "input.paste", annotations: isolateHistory.of("full") });
            view.focus();
            return view.state.doc !== before;
        },
        positionAt(event) { return view.posAtCoords({ x: event.clientX, y: event.clientY }) ?? view.state.selection.main.head; },
        show(visible) { host.hidden = !visible; if (visible) view.focus(); },
        destroy() {
            observer.disconnect();
            clearTimeout(resetTimer);
            document.removeEventListener("reset", reset, true);
            delete textarea.value;
            textarea.removeEventListener("invalid", focus);
            labels.forEach(label => label.removeEventListener("click", focus));
            view.destroy();
            textarea.hidden = wasHidden;
        },
    };
    // Programmatic writes, including a framework's controlled value, update
    // the editor without an input event, like a native textarea.
    Object.defineProperty(textarea, "value", {
        configurable: true,
        get() { return native.get.call(textarea); },
        set(value) { native.set.call(textarea, value); api.setValue(native.get.call(textarea), false); },
    });
    // Reset does not bubble; capturing at the document follows the field into
    // whichever form currently owns it.
    let resetTimer;
    const reset = event => {
        if (event.target === textarea.form) resetTimer = setTimeout(() => api.setValue(textarea.value), 0);
    };
    document.addEventListener("reset", reset, true);
    return api;
}

// Explicit host children keep framework-owned nodes separate from CodeMirror's
// DOM. Disconnect cleanup also covers Dioxus navigation and Topcoat fragments.
if (typeof customElements !== "undefined" && !customElements.get("oxidt-markdown-editor")) {
    customElements.define("oxidt-markdown-editor", class extends HTMLElement {
        connectedCallback() {
            queueMicrotask(() => {
                if (!this.isConnected || this.editor) return;
                const textarea = this.querySelector("textarea");
                const host = this.querySelector("[data-editor-host]");
                if (!textarea || !host) return;
                this.style.display = "block";
                this.style.minWidth = "0";
                this.editor = mountEditor(textarea, host);
            });
        }
        disconnectedCallback() {
            queueMicrotask(() => {
                if (this.isConnected) return;
                this.editor?.destroy();
                this.editor = null;
            });
        }
    });
}
