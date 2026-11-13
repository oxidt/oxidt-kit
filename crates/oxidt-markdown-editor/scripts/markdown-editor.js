import { Compartment, EditorState, Prec, StateEffect, StateField } from "@codemirror/state";
import { Decoration, EditorView, ViewPlugin, WidgetType, keymap, placeholder } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, isolateHistory } from "@codemirror/commands";
import { Language, LanguageSupport, syntaxTree } from "@codemirror/language";
import { commonmarkLanguage, markdownKeymap } from "@codemirror/lang-markdown";
import { Strikethrough, Table, TaskList } from "@lezer/markdown";
import { autocompletion, pickedCompletion } from "@codemirror/autocomplete";
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

// A `[[target|label]]` the host resolved: its title (or label) as one unit. The source
// shows when the cursor enters it (a click, or an arrow key from its edge).
class WikiLinkWidget extends WidgetType {
    constructor(text, href, target, hint) { super(); Object.assign(this, { text, href, target, hint }); }
    eq(other) { return other.text === this.text && other.href === this.href && other.target === this.target && other.hint === this.hint; }
    toDOM() {
        const link = document.createElement("span");
        link.className = "md-link md-wiki-link";
        link.textContent = this.text;
        link.dataset.target = this.target;
        if (this.href) link.dataset.href = this.href;
        if (this.hint) link.title = this.hint;
        return link;
    }
    ignoreEvent() { return false; }
}

const apple = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
/// The modifier that opens a link while editing: Cmd on Apple platforms, else Ctrl.
const openHint = apple ? "⌘+click to open" : "Ctrl+click to open";
const opens = event => (apple ? event.metaKey : event.ctrlKey);

// ── Links: a bracketed word is a link only with a destination or a defined reference
//    label, as in CommonMark. ──

const normalizeLabel = text => text.trim().replace(/\s+/g, " ").toLowerCase();

/// The labels defined by reference definitions (`[label]: https://…`).
function definedLabels(state) {
    const labels = new Set();
    syntaxTree(state).iterate({
        enter({ node, name }) {
            if (name === "LinkReference") {
                const label = node.getChild("LinkLabel");
                if (label) labels.add(normalizeLabel(state.sliceDoc(label.from + 1, label.to - 1)));
                return false;
            }
            // Definitions are blocks: inline content holds none.
            if (name === "Paragraph" || /^(ATX|Setext)Heading/.test(name) || name === "FencedCode" || name === "CodeBlock" || name === "Table") return false;
        },
    });
    return labels;
}

/// Whether a `Link` node is a link: `[text](url)`, or `[text][label]`, `[text][]` or
/// `[text]` whose label is defined. `[x]` alone is ordinary text.
export function isLink(state, node, labels) {
    if (node.getChild("URL")) return true;
    const close = node.getChildren("LinkMark").find(mark => state.sliceDoc(mark.from, mark.to) === "]");
    if (!close) return false;
    const text = state.sliceDoc(node.from + 1, close.from);
    const label = node.getChild("LinkLabel");
    const named = label ? state.sliceDoc(label.from + 1, label.to - 1) : "";
    return labels.has(normalizeLabel(named.trim() ? named : text));
}

// ── `[[target|label]]` links, when the host opts in (`data-wiki-links`): it resolves each
//    target to `{ title, href }` or nothing (`markdown-resolve`). ──

/// Answers from the host, by target: `{ title, href }`, or `null` for one that resolves to
/// nothing. A target without an answer yet shows as plain text.
export const setResolved = StateEffect.define();
export const wikiLinkField = StateField.define({
    create: () => new Map(),
    update(value, transaction) {
        for (const effect of transaction.effects) {
            if (effect.is(setResolved)) value = new Map([...value, ...effect.value]);
        }
        return value;
    },
});

const literal = new Set(["InlineCode", "FencedCode", "CodeBlock", "HTMLBlock", "HTMLTag", "URL", "Image", "Autolink", "Comment", "CommentBlock", "ProcessingInstruction"]);

/// The `[[target|label]]` links on the lines from `from` to `to`, outside code, HTML,
/// images and links with a destination; `\[[` is literal.
export function wikiLinks(state, from = 0, to = state.doc.length) {
    const links = [];
    const tree = syntaxTree(state);
    for (let pos = state.doc.lineAt(from).from; pos <= to;) {
        const line = state.doc.lineAt(pos);
        for (const match of line.text.matchAll(/\[\[([^\[\]\n]+)\]\]/g)) {
            const start = line.from + match.index;
            // `\[[` is literal; `[[a]](url)` is a Markdown link whose text is `[a]`.
            if (line.text[match.index - 1] === "\\" || line.text[match.index + match[0].length] === "(") continue;
            let inside = false;
            for (let node = tree.resolveInner(start + 2, 1); node; node = node.parent) {
                if (literal.has(node.name) || (node.name === "Link" && node.getChild("URL"))) { inside = true; break; }
            }
            if (inside) continue;
            const [target, ...label] = match[1].split("|");
            if (!target.trim()) continue;
            links.push({ from: start, to: start + match[0].length, target: target.trim(), label: label.join("|").trim() || null });
        }
        if (line.to >= state.doc.length) break;
        pos = line.to + 1;
    }
    return links;
}

/// Whether a selection range is inside a link: the cursor strictly within it, or a
/// selection overlapping it.
const within = (state, from, to) => state.selection.ranges.some(range =>
    range.empty ? from < range.head && range.head < to : range.from < to && range.to > from);

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

// Ticking the box rewrites the marker in the Markdown, as typing would.
class TaskBox extends WidgetType {
    constructor(checked) { super(); this.checked = checked; }
    eq(other) { return other.checked === this.checked; }
    toDOM(view) {
        const box = document.createElement("input");
        box.type = "checkbox";
        box.className = "md-task";
        box.checked = this.checked;
        box.disabled = view.state.readOnly;
        box.addEventListener("mousedown", event => event.preventDefault());
        box.addEventListener("click", event => {
            event.preventDefault();
            const from = view.posAtDOM(box);
            view.dispatch({ changes: { from: from + 1, to: from + 2, insert: this.checked ? " " : "x" } });
        });
        return box;
    }
    ignoreEvent() { return true; }
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
    let labels = null;
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
                labels ??= definedLabels(state);
                if (!isLink(state, node, labels)) return;
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
                    // A task's checkbox stands in for the bullet.
                    const task = node.parent.getChild("Task");
                    if (task) hide(from, task.from);
                    else result.push(Decoration.replace({ widget: new Bullet() }).range(from, to));
                }
            } else if (name === "TaskMarker") {
                const checked = state.sliceDoc(from + 1, from + 2) !== " ";
                if (!editing(from, to)) result.push(Decoration.replace({ widget: new TaskBox(checked) }).range(from, to));
                // The text after the marker, without the space between them.
                if (checked) mark(state.sliceDoc(to, to + 1) === " " ? to + 1 : to, node.parent.to, "md-task-done");
            } else if (name === "Blockquote") {
                lines(from, to, "md-quote");
            } else if (name === "QuoteMark") {
                hide(from, state.sliceDoc(to, to + 1) === " " ? to + 1 : to);
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
    const resolved = state.field(wikiLinkField, false);
    if (resolved) {
        const covered = [];
        const seen = new Set();
        const editable = !state.readOnly && state.facet(EditorView.editable);
        for (const range of ranges) for (const link of wikiLinks(state, range.from, range.to)) {
            if (seen.has(link.from)) continue;
            seen.add(link.from);
            const answer = resolved.get(link.target);
            if (!answer) continue;
            if (focused && within(state, link.from, link.to)) {
                mark(link.from, link.to, "md-link");
            } else {
                const widget = new WikiLinkWidget(link.label || answer.title, answer.href, link.target, editable ? openHint : "");
                covered.push(Decoration.replace({ widget }).range(link.from, link.to));
            }
        }
        // Formatting inside a link's source gives way to the link shown in its place.
        if (covered.length) {
            const kept = result.filter(item => !covered.some(link => item.from >= link.from && item.to <= link.to));
            result.length = 0;
            result.push(...kept, ...covered);
        }
    }
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

// A shown `[[link]]` is one unit for the cursor and for deleting.
const shownLinks = set => set.update({ filter: (from, to, value) => value.spec.widget instanceof WikiLinkWidget });

const livePreview = ViewPlugin.fromClass(class {
    constructor(view) { this.decorations = decorations(view.state, view.hasFocus, view.visibleRanges); }
    update(update) {
        if (update.docChanged || update.selectionSet || update.viewportChanged || update.focusChanged ||
            syntaxTree(update.startState) !== syntaxTree(update.state) ||
            update.state.field(wikiLinkField, false) !== update.startState.field(wikiLinkField, false)) {
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
    ".md-task": { width: "1em", height: "1em", margin: "0 0.5em 0 0", verticalAlign: "-0.12em", cursor: "pointer", accentColor: "var(--md-editor-accent, var(--color-primary, #146ade))" },
    ".md-task-done": { textDecoration: "line-through", color: "color-mix(in srgb, var(--md-editor-color, var(--color-base-content, #202936)) 55%, transparent)" },
    ".md-quote": { borderLeft: "3px solid var(--md-editor-border, var(--color-base-300, #d1d5db))", paddingLeft: "0.9rem", color: "color-mix(in srgb, var(--md-editor-color, var(--color-base-content, #202936)) 75%, transparent)" },
    ".md-bullet": { display: "inline-block", width: "0.7em", textAlign: "center", color: "var(--md-editor-accent, var(--color-primary, #146ade))" },
    ".cm-tooltip-autocomplete": { fontFamily: "inherit", backgroundColor: "var(--md-editor-background, var(--color-base-100, #fff))", color: "var(--md-editor-color, var(--color-base-content, #202936))", border: "1px solid var(--md-editor-border, var(--color-base-300, #d1d5db))", borderRadius: "0.5rem", overflow: "hidden", boxShadow: "0 4px 16px #0002" },
    ".cm-tooltip.cm-tooltip-autocomplete > ul": { fontFamily: "inherit", maxHeight: "min(20rem, 50vh)" },
    ".cm-tooltip.cm-tooltip-autocomplete > ul > li": { padding: "0.35rem 0.65rem", lineHeight: "1.5" },
    ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--md-editor-code-background, var(--color-base-200, #f1f3f5))", color: "var(--md-editor-color, var(--color-base-content, #202936))" },
    ".cm-completionDetail": { fontStyle: "normal", opacity: "0.65", marginLeft: "1rem" },
});

// ── Host hooks, all opt-in and answered through events on the textarea. ──

/// Asks the host through a cancelable `type` event on `textarea`; the host claims it with
/// `preventDefault()` and answers by calling `detail.respond(answer)`, now or later.
/// Unclaimed, unanswered within `wait` ms, or aborted: `null`.
function ask(textarea, type, detail, wait = 5000, signal) {
    return new Promise(resolve => {
        let done = false;
        const finish = answer => { if (!done) { done = true; clearTimeout(timer); resolve(answer); } };
        const timer = setTimeout(() => finish(null), wait);
        signal?.addEventListener("abort", () => finish(null));
        const event = new CustomEvent(type, { bubbles: true, cancelable: true, detail: { ...detail, respond: finish } });
        textarea.dispatchEvent(event);
        if (!event.defaultPrevented) finish(null);
    });
}

/// The triggers the host completes (`data-completion-triggers`, a JSON array such as
/// `["[["]`).
function completionTriggers(textarea) {
    try {
        const triggers = JSON.parse(textarea.dataset.completionTriggers || "[]");
        return Array.isArray(triggers) ? triggers.filter(t => typeof t === "string" && t) : [];
    } catch { return []; }
}

/// Completions for the host's triggers, shown in the editor's own menu. Typing a trigger
/// and up to 100 characters (no line break, none of the trigger's characters) sends a
/// `markdown-complete` event with `{ trigger, query }`; the host answers
/// `[{ label, detail?, insert }]`, and a pick replaces the trigger and query with `insert`
/// as one undo step.
export function hostCompletions(textarea) {
    return async context => {
        const { state, pos } = context;
        const triggers = completionTriggers(textarea);
        if (!triggers.length || state.readOnly || !state.facet(EditorView.editable) ||
            state.selection.ranges.length !== 1 || !state.selection.main.empty) return null;
        const line = state.doc.lineAt(pos);
        const before = line.text.slice(0, pos - line.from);
        for (const trigger of triggers) {
            const at = before.lastIndexOf(trigger);
            if (at < 0) continue;
            const query = before.slice(at + trigger.length);
            if (query.length > 100 || [...trigger].some(c => query.includes(c))) continue;
            if (at > 0 && before[at - 1] === "\\") continue;
            let code = false;
            for (let node = syntaxTree(state).resolveInner(pos, -1); node; node = node.parent) {
                if (literal.has(node.name)) { code = true; break; }
            }
            if (code) return null;
            const signal = new AbortController();
            context.addEventListener("abort", () => signal.abort());
            const items = await ask(textarea, "markdown-complete", { trigger, query }, 5000, signal.signal);
            if (!Array.isArray(items) || context.aborted) return null;
            const options = items.filter(item => item && typeof item.label === "string" && typeof item.insert === "string")
                .map(item => ({
                    label: item.label,
                    detail: typeof item.detail === "string" ? item.detail : undefined,
                    apply(view, completion, from, to) {
                        if (view.state.readOnly || !view.state.facet(EditorView.editable)) return;
                        view.dispatch({
                            changes: { from, to, insert: item.insert },
                            selection: { anchor: from + item.insert.length },
                            scrollIntoView: true,
                            userEvent: "input.complete",
                            annotations: [pickedCompletion.of(completion), isolateHistory.of("full")],
                        });
                    },
                }));
            // Every answer comes from the host; nothing is filtered here.
            return { from: line.from + at, to: pos, options, filter: false };
        }
        return null;
    };
}

const refreshLinks = StateEffect.define();

/// Asks the host to resolve the `[[links]]` in view that it has not answered
/// (`markdown-resolve` with `{ targets }`; the answer maps each target to
/// `{ title, href }` or `null`), and all of them again on `refreshLinks`.
function linkResolver(textarea) {
    return ViewPlugin.fromClass(class {
        constructor(view) { this.view = view; this.asked = new Set(); this.ask(); }
        update(update) {
            const refreshed = update.transactions.some(tr => tr.effects.some(effect => effect.is(refreshLinks)));
            if (refreshed) this.asked.clear();
            if (refreshed || update.docChanged || update.viewportChanged) this.ask();
        }
        ask() {
            const { state } = this.view;
            const targets = new Set();
            for (const range of this.view.visibleRanges) {
                for (const link of wikiLinks(state, range.from, range.to)) {
                    if (!this.asked.has(link.target)) targets.add(link.target);
                }
            }
            if (!targets.size) return;
            for (const target of targets) this.asked.add(target);
            // Not during an update: an answer given at once dispatches.
            setTimeout(async () => {
                const answer = await ask(textarea, "markdown-resolve", { targets: [...targets] }, 10000);
                if (!answer || typeof answer !== "object" || this.destroyed) {
                    for (const target of targets) this.asked.delete(target);
                    return;
                }
                const entries = [...targets].map(target => {
                    const found = answer[target];
                    return [target, found && typeof found.title === "string"
                        ? { title: found.title, href: typeof found.href === "string" ? found.href : "" } : null];
                });
                this.view.dispatch({ effects: setResolved.of(entries) });
            });
        }
        destroy() { this.destroyed = true; }
    });
}

/// The link at `pos`: a `[[target]]` (with its answer) or a Markdown link with a destination.
function linkAt(state, pos) {
    const wiki = wikiLinks(state, pos, pos).find(link => link.from <= pos && pos <= link.to);
    if (wiki) {
        const answer = state.field(wikiLinkField, false)?.get(wiki.target);
        return { kind: "wiki", target: wiki.target, href: answer?.href || null };
    }
    for (let node = syntaxTree(state).resolveInner(pos, 0); node; node = node.parent) {
        if (node.name === "Image") return null;
        if (node.name === "Link") {
            const url = node.getChild("URL");
            return url ? { kind: "link", target: null, href: state.sliceDoc(url.from, url.to) } : null;
        }
    }
    return null;
}

/// A click on a link: read-only, a plain click; editing, Cmd/Ctrl+click (shown as the
/// shown link's tooltip). Sends `markdown-link` with `{ kind: "wiki" | "link", target, href }`;
/// when the host claims it (`preventDefault()`), the click does nothing else. A plain click
/// on a shown `[[link]]` while editing moves the cursor into it, which shows its source.
function activateLink(textarea, event, view) {
    if (event.button !== 0) return false;
    const locked = view.state.readOnly || !view.state.facet(EditorView.editable);
    const shown = event.target.closest?.(".md-wiki-link");
    if (shown && !locked && !opens(event)) {
        event.preventDefault();
        view.dispatch({ selection: { anchor: view.posAtDOM(shown) + 2 } });
        view.focus();
        return true;
    }
    if (!locked && !opens(event)) return false;
    let link;
    if (shown) link = { kind: "wiki", target: shown.dataset.target, href: shown.dataset.href || null };
    else {
        const pos = view.posAtCoords({ x: event.clientX, y: event.clientY });
        link = pos == null ? null : linkAt(view.state, pos);
    }
    if (!link) return false;
    const claimed = !textarea.dispatchEvent(new CustomEvent("markdown-link", { bubbles: true, cancelable: true, detail: link }));
    if (claimed) event.preventDefault();
    return claimed;
}

/// An arrow key at the edge of a shown `[[link]]` moves into it, which shows its source.
const enterLink = forward => view => {
    const { state } = view;
    const range = state.selection.main;
    if (!range.empty || !state.field(wikiLinkField, false)) return false;
    const link = wikiLinks(state, range.head, range.head).find(link =>
        (forward ? link.from === range.head : link.to === range.head) && state.field(wikiLinkField).get(link.target));
    if (!link) return false;
    view.dispatch({ selection: { anchor: forward ? link.from + 1 : link.to - 1 }, scrollIntoView: true });
    return true;
};
const wikiKeys = [{ key: "ArrowRight", run: enterLink(true) }, { key: "ArrowLeft", run: enterLink(false) }];

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
    // CodeMirror lives in a shadow root: frameworks that patch server HTML in
    // place (Topcoat shards, live updates) see an empty host on both sides
    // and leave the editor alone.
    const root = host.shadowRoot ?? host.attachShadow({ mode: "open" });
    const view = new EditorView({
        parent: root,
        root,
        doc: textarea.value,
        selection: { anchor: textarea.selectionStart, head: textarea.selectionEnd },
        extensions: [
            // markdown() would also bundle lang-html, css and javascript for
            // features this editor leaves off; only its list keymap is kept.
            new LanguageSupport(new Language(commonmarkLanguage.data, commonmarkLanguage.parser.configure([Strikethrough, Table, TaskList]), [], "markdown")),
            Prec.high(keymap.of(markdownKeymap)),
            history(), keymap.of([...defaultKeymap, ...historyKeymap]), controls.of(controlled()),
            autocompletion({ override: [slashCommands(commandLabels(textarea)), hostCompletions(textarea)], icons: false, activateOnTypingDelay: 0, interactionDelay: 0 }),
            textarea.hasAttribute("data-wiki-links") ? [
                wikiLinkField, linkResolver(textarea), Prec.high(keymap.of(wikiKeys)),
                EditorView.atomicRanges.of(view => shownLinks(view.plugin(livePreview)?.decorations ?? Decoration.none)),
            ] : [],
            EditorView.domEventHandlers({ mousedown: (event, view) => activateLink(textarea, event, view) }),
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
    // The stylesheet hides the textarea (an attribute would be reverted by a
    // framework re-render); a field hidden by its author keeps the editor hidden.
    host.hidden = textarea.hidden;
    if (hadFocus) view.focus();
    // A re-render may replace the textarea's text, which changes a pristine
    // field's value without the setter. Follow it unless the user has edited.
    let pristine = textarea.value;
    const follow = new MutationObserver(() => {
        const value = native.get.call(textarea);
        if (view.state.doc.toString() === pristine && value !== pristine) api.setValue(value, false);
        pristine = value;
    });
    follow.observe(textarea, { childList: true, characterData: true, subtree: true });
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
        replace(from, to, text) {
            if (locked() || from < 0 || to < from || to > view.state.doc.length) return false;
            const length = view.state.doc.length - (to - from) + text.length;
            if (textarea.maxLength >= 0 && length > textarea.maxLength && length > view.state.doc.length) return false;
            view.dispatch({ changes: { from, to, insert: text }, selection: { anchor: from + text.length }, scrollIntoView: true, userEvent: "input", annotations: isolateHistory.of("full") });
            view.focus();
            return true;
        },
        refreshLinks() { view.dispatch({ effects: refreshLinks.of(null) }); },
        positionAt(event) { return view.posAtCoords({ x: event.clientX, y: event.clientY }) ?? view.state.selection.main.head; },
        show(visible) { host.hidden = !visible; if (visible) view.focus(); },
        destroy() {
            observer.disconnect();
            follow.disconnect();
            clearTimeout(resetTimer);
            document.removeEventListener("reset", reset, true);
            delete textarea.value;
            textarea.removeEventListener("invalid", focus);
            labels.forEach(label => label.removeEventListener("click", focus));
            view.destroy();
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

/// `data-labels` on the textarea: a JSON object of slash-command labels.
function commandLabels(textarea) {
    try {
        const labels = JSON.parse(textarea.dataset.labels || "{}");
        return labels && typeof labels === "object" ? labels : {};
    } catch { return {}; }
}

// Layout and the hidden textarea come from a stylesheet rather than inline
// styles or attributes, which a framework's in-place re-render would undo.
function installStyles() {
    if (document.getElementById("oxidt-markdown-editor-styles")) return;
    const style = document.createElement("style");
    style.id = "oxidt-markdown-editor-styles";
    style.textContent = "oxidt-markdown-editor{display:block;min-width:0}" +
        "oxidt-markdown-editor:defined:has(> [data-editor-host]) > textarea{display:none}";
    document.head.append(style);
}

// Explicit host children keep framework-owned nodes separate from CodeMirror's
// DOM. Disconnect cleanup also covers Dioxus navigation and Topcoat fragments.
if (typeof customElements !== "undefined" && !customElements.get("oxidt-markdown-editor")) {
    installStyles();
    customElements.define("oxidt-markdown-editor", class extends HTMLElement {
        connectedCallback() {
            queueMicrotask(() => {
                if (!this.isConnected || this.editor) return;
                const textarea = this.querySelector("textarea");
                const host = this.querySelector("[data-editor-host]");
                if (!textarea || !host) return;
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
