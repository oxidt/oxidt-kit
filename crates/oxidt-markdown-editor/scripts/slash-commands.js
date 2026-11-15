import { pickedCompletion, startCompletion } from "@codemirror/autocomplete";
import { isolateHistory } from "@codemirror/commands";
import { syntaxTree } from "@codemirror/language";
import { EditorView } from "@codemirror/view";

// The typed command names stay English; `detail` is the shown, translatable
// label (see `labels` in the README).
const defaults = [
    ["heading-1", "Heading 1", "# "],
    ["heading-2", "Heading 2", "## "],
    ["heading-3", "Heading 3", "### "],
    ["bullet-list", "Bullet list", "- "],
    ["numbered-list", "Numbered list", "1. "],
    ["task-list", "Task list", "- [ ] "],
    ["quote", "Quote", "> "],
    ["code", "Code block", "```\n\n```", 4],
    ["diagram", "Mermaid diagram", "```mermaid\nflowchart LR\n    A --> B\n```", 10],
];

const command = labels => ([name, detail, insert, cursor = insert.length]) => ({
    label: "/" + name,
    detail: typeof labels[name] === "string" && labels[name] ? labels[name] : detail,
    apply(view, completion, from, to) {
        if (view.state.readOnly || !view.state.facet(EditorView.editable)) return;
        view.dispatch({
            changes: { from, to, insert },
            selection: { anchor: from + cursor },
            scrollIntoView: true,
            userEvent: "input.complete",
            annotations: [pickedCompletion.of(completion), isolateHistory.of("full")],
        });
    },
});

// `/link` writes `[[` and opens the host's completions for it, for keyboards where `[`
// is hard to reach. Unlike the block commands it also works within a line.
const link = labels => ({
    ...command(labels)(["link", "Link to page", "[["]),
    apply(view, completion, from, to) {
        if (view.state.readOnly || !view.state.facet(EditorView.editable)) return;
        view.dispatch({
            changes: { from, to, insert: "[[" },
            selection: { anchor: from + 2 },
            scrollIntoView: true,
            userEvent: "input.complete",
            annotations: [pickedCompletion.of(completion), isolateHistory.of("full")],
        });
        startCompletion(view);
    },
});

/// The completion source, with `labels` mapping command names to the text
/// shown beside them (e.g. `{ "heading-1": "Überschrift 1" }`). `linking` says
/// whether the host completes `[[` now; only then is `/link` offered.
export function slashCommands(labels = {}, linking = () => false) {
    const commands = defaults.map(command(labels));
    const linkCommand = link(labels);
    return context => slashSource(commands, linking() ? linkCommand : null, context);
}

// Only a command on its own line opens the menu (`/link` also after a space
// within a line). Paths, URLs, selections, and Markdown inside code or HTML
// keep their ordinary typing behavior.
function slashSource(commands, linkCommand, { state, pos }) {
    if (state.readOnly || !state.facet(EditorView.editable) ||
        state.selection.ranges.length !== 1 || !state.selection.main.empty) return null;
    const line = state.doc.lineAt(pos);
    const typed = /(?:^|\s)(\/[a-z0-9-]*)$/.exec(line.text.slice(0, pos - line.from))?.[1];
    if (!typed) return null;
    for (let node = syntaxTree(state).resolveInner(pos, -1); node; node = node.parent) {
        if (["FencedCode", "CodeBlock", "HTMLBlock", "InlineCode"].includes(node.name)) return null;
    }
    const options = pos === line.to && line.text === typed ? commands.filter(command => command.label.startsWith(typed)) : [];
    if (linkCommand?.label.startsWith(typed)) options.push(linkCommand);
    return options.length ? { from: pos - typed.length, options, filter: false } : null;
}
