import { expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { commonmarkLanguage, markdown } from "@codemirror/lang-markdown";
import { Table } from "@lezer/markdown";
import { decorations, tables } from "./markdown-editor.js";

function render(doc, selection, focused = true, visible) {
    const state = EditorState.create({ doc, selection, extensions: [markdown({ base: commonmarkLanguage })] });
    const ranges = [];
    for (let cursor = decorations(state, focused, visible).iter(); cursor.value; cursor.next()) {
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

test("raw HTML remains literal", () => {
    expect(render("<script>alert('test')</script>", { anchor: 0 }, false).ranges).toEqual([]);
});

test("images render and reveal their Markdown when editing", () => {
    const doc = "Intro\n![A *chart*](https://example.com/c.png)";
    const [image] = render(doc, { anchor: 0 }).ranges.filter(range => range.widget);
    expect(image.widget).toMatchObject({ src: "https://example.com/c.png", alt: "A *chart*" });
    expect([image.from, image.to]).toEqual([6, doc.length]);
    expect(render(doc, { anchor: doc.length }).ranges.some(range => range.widget)).toBe(false);
});

test("every visible range is decorated when a block widget splits the viewport", () => {
    const doc = "**a**\n\nskipped\n\n**b**";
    const ranges = render(doc, { anchor: 0 }, false, [{ from: 0, to: 5 }, { from: 16, to: 21 }]).ranges;
    expect(ranges.filter(range => range.class === "md-strong").map(range => range.from)).toEqual([0, 16]);
});

function tableRanges(doc, selection, focused = true) {
    const state = EditorState.create({ doc, selection, extensions: [markdown({ base: commonmarkLanguage, extensions: [Table] })] });
    const ranges = [];
    for (let cursor = tables(state, focused).iter(); cursor.value; cursor.next()) {
        ranges.push({ from: cursor.from, to: cursor.to, ...cursor.value.spec });
    }
    return ranges;
}

test("tables render as a block and reveal their Markdown when editing", () => {
    const table = "| Plan | Price |\n| --- | --- |\n| Pro | **$9** |";
    const doc = "Intro\n\n" + table + "\n\nAfter";
    const [block] = tableRanges(doc, { anchor: 0 });
    expect(block).toMatchObject({ from: 7, to: 7 + table.length, block: true });
    expect(block.widget.rows).toEqual([["Plan", "Price"], ["Pro", "**$9**"]]);
    expect(tableRanges(doc, { anchor: 7 + table.length })).toEqual([]);
    expect(tableRanges(doc, { anchor: 7 + table.length }, false)).toHaveLength(1);
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

test("every visible range is decorated", () => {
    const doc = "**a**\n\n**b**";
    expect(render(doc, { anchor: 0 }, false, [{ from: 0, to: 5 }, { from: 7, to: 12 }]).ranges)
        .toEqual(render(doc, { anchor: 0 }, false).ranges);
});
