import { expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { commonmarkLanguage, markdown } from "@codemirror/lang-markdown";
import { decorations } from "./markdown-editor.js";

function render(doc, selection, focused = true) {
    const state = EditorState.create({ doc, selection, extensions: [markdown({ base: commonmarkLanguage })] });
    const ranges = [];
    for (let cursor = decorations(state, focused).iter(); cursor.value; cursor.next()) {
        ranges.push({ from: cursor.from, to: cursor.to, ...cursor.value.spec });
    }
    return { state, ranges, hidden: ranges.filter(range => range.from < range.to && !range.class && !range.widget) };
}

test("headings style immediately but markers stay editable on the active line", () => {
    const { ranges, hidden } = render("## Heading\n\nBody", { anchor: 5 });
    expect(ranges.some(range => range.class === "md-h2")).toBe(true);
    expect(hidden).toEqual([]);
    expect(render("## Heading\n\nBody", { anchor: 14 }).hidden).toEqual([{ from: 0, to: 3 }]);
});

test("leaving the field hides syntax without changing the Markdown", () => {
    const doc = "**bold** and *italic*";
    const { state, hidden } = render(doc, { anchor: 3 }, false);
    expect(hidden).toHaveLength(4);
    expect(state.doc.toString()).toBe(doc);
});

test("all selected lines expose syntax for editing and copying", () => {
    const doc = "## Heading\n\n**bold**";
    expect(render(doc, { anchor: 0, head: doc.length }).hidden).toEqual([]);
});

test("nested emphasis renders but escaped markers remain literal", () => {
    const { ranges, hidden } = render("**bold and *italic***\n\n\\*literal\\*", { anchor: 0 }, false);
    expect(ranges.filter(range => ["md-em", "md-strong"].includes(range.class))).toHaveLength(2);
    expect(hidden).toHaveLength(4);
});

test("code fences preserve literal Markdown inside the block", () => {
    const doc = "```rust\n**not bold**\n```";
    const { ranges, hidden } = render(doc, { anchor: 0 }, false);
    expect(ranges.filter(range => range.class === "md-code-line")).toHaveLength(3);
    expect(ranges.some(range => range.class === "md-strong")).toBe(false);
    expect(hidden.map(range => doc.slice(range.from, range.to))).toEqual(["```", "rust", "```"]);
});

test("links display the label and reveal the destination when editing", () => {
    const doc = "[**Label**](https://example.com)";
    const { hidden } = render(doc, { anchor: 0 }, false);
    expect(hidden.map(range => doc.slice(range.from, range.to))).toEqual(["[", "**", "**", "](https://example.com)"]);
    expect(render(doc, { anchor: 5 }).hidden).toEqual([]);
});

test("image Markdown and raw HTML remain literal", () => {
    for (const doc of ["![alt](image.png)", "<script>alert('test')</script>"]) {
        expect(render(doc, { anchor: 0 }, false).hidden).toEqual([]);
    }
});

test("multiline emphasis never hides a line break", () => {
    const doc = "**first\nsecond**";
    for (const range of render(doc, { anchor: 0 }, false).hidden) {
        expect(doc.slice(range.from, range.to)).not.toContain("\n");
    }
});

test("bullet widgets preserve ordered list numbering", () => {
    expect(render("- item", { anchor: 0 }, false).ranges.some(range => range.widget)).toBe(true);
    expect(render("1. item", { anchor: 0 }, false).ranges.some(range => range.widget)).toBe(false);
});
