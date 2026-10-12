import { pickedCompletion } from "@codemirror/autocomplete";
import { isolateHistory } from "@codemirror/commands";
import { syntaxTree } from "@codemirror/language";
import { EditorView } from "@codemirror/view";

const commands = [
    ["heading-1", "Heading 1", "# "],
    ["heading-2", "Heading 2", "## "],
    ["heading-3", "Heading 3", "### "],
    ["bullet-list", "Bullet list", "- "],
    ["numbered-list", "Numbered list", "1. "],
    ["task-list", "Task list", "- [ ] "],
    ["quote", "Quote", "> "],
    ["code", "Code block", "```\n\n```", 4],
].map(([name, detail, insert, cursor = insert.length]) => ({
    label: "/" + name,
    detail,
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
}));

// Only a command on its own line opens the menu. Paths, URLs, selections,
// and Markdown inside code or HTML keep their ordinary typing behavior.
export function slashCommands({ state, pos }) {
    if (state.readOnly || !state.facet(EditorView.editable) ||
        state.selection.ranges.length !== 1 || !state.selection.main.empty) return null;
    const line = state.doc.lineAt(pos);
    if (pos !== line.to || !/^\/[a-z0-9-]*$/.test(line.text)) return null;
    for (let node = syntaxTree(state).resolveInner(pos, -1); node; node = node.parent) {
        if (["FencedCode", "CodeBlock", "HTMLBlock", "InlineCode"].includes(node.name)) return null;
    }
    const options = commands.filter(command => command.label.startsWith(line.text));
    return options.length ? { from: line.from, options, filter: false } : null;
}
