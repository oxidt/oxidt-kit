import { expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { commonmarkLanguage, markdown } from "@codemirror/lang-markdown";
import { Table, TaskList } from "@lezer/markdown";
import { decorations, blocks, wikiLinks, wikiLinkField, setResolved } from "./markdown-editor.js";

function render(doc, selection, focused = true, visible) {
    const state = EditorState.create({ doc, selection, extensions: [markdown({ base: commonmarkLanguage, extensions: [TaskList] })] });
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

function blockRanges(doc, selection, focused = true) {
    const state = EditorState.create({ doc, selection, extensions: [markdown({ base: commonmarkLanguage, extensions: [Table] })] });
    const ranges = [];
    for (let cursor = blocks(state, focused).iter(); cursor.value; cursor.next()) {
        ranges.push({ from: cursor.from, to: cursor.to, ...cursor.value.spec });
    }
    return ranges;
}

test("tables render as a block and reveal their Markdown when editing", () => {
    const table = "| Plan | Price |\n| --- | --- |\n| Pro | **$9** |";
    const doc = "Intro\n\n" + table + "\n\nAfter";
    const [block] = blockRanges(doc, { anchor: 0 });
    expect(block).toMatchObject({ from: 7, to: 7 + table.length, block: true });
    expect(block.widget.rows).toEqual([["Plan", "Price"], ["Pro", "**$9**"]]);
    expect(blockRanges(doc, { anchor: 7 + table.length })).toEqual([]);
    expect(blockRanges(doc, { anchor: 7 + table.length }, false)).toHaveLength(1);
});

test("Mermaid fences render as blocks and expose the entire source when selected", () => {
    const diagram = "```mermaid\nflowchart LR\n    A --> B\n```";
    const doc = "Intro\n\n" + diagram + "\n\nAfter";
    const [block] = blockRanges(doc, { anchor: 0 });
    expect(block).toMatchObject({ from: 7, to: 7 + diagram.length, block: true });
    expect(block.widget.source).toBe("flowchart LR\n    A --> B");
    for (const anchor of [7, 20, 7 + diagram.length]) {
        expect(blockRanges(doc, { anchor })).toEqual([]);
        expect(render(doc, { anchor }).hidden).toEqual([]);
    }
    expect(blockRanges(doc, { anchor: 0, head: doc.length })).toEqual([]);
    expect(blockRanges(doc, { anchor: 20 }, false)).toHaveLength(1);
});

test("diagram extraction supports tilde fences and nested Markdown containers", () => {
    for (const doc of [
        "~~~mermaid\nflowchart LR\n  A-->B\n~~~",
        "> ```mermaid\n> flowchart LR\n>   A-->B\n> ```",
        "- ```mermaid\n  flowchart LR\n    A-->B\n  ```",
    ]) {
        expect(blockRanges(doc, { anchor: 0 }, false)[0].widget.source).toBe("flowchart LR\n  A-->B");
    }
});

test("ordinary, unclosed, and indented fences stay code", () => {
    for (const doc of ["```js\nflowchart LR\n A-->B\n```", "```mermaid\nflowchart LR", "    ```mermaid\n    flowchart LR\n    ```"]) {
        expect(blockRanges(doc, { anchor: 0 }, false)).toEqual([]);
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

test("every visible range is decorated", () => {
    const doc = "**a**\n\n**b**";
    expect(render(doc, { anchor: 0 }, false, [{ from: 0, to: 5 }, { from: 7, to: 12 }]).ranges)
        .toEqual(render(doc, { anchor: 0 }, false).ranges);
});

test("task items show a checkbox instead of the bullet and the brackets", () => {
    const doc = "- [ ] open\n- [x] done\n\ntext";
    const { ranges, hidden } = render(doc, { anchor: doc.length });
    const boxes = ranges.filter(range => range.widget);
    expect(boxes.map(range => [doc.slice(range.from, range.to), range.widget.checked])).toEqual([["[ ]", false], ["[x]", true]]);
    expect(hidden.map(range => doc.slice(range.from, range.to))).toEqual(["- ", "- "]);
    expect(ranges.filter(range => range.class === "md-task-done").map(range => doc.slice(range.from, range.to))).toEqual(["done"]);
});

test("a task on the active line shows its Markdown", () => {
    const doc = "- [ ] open\n- [x] done";
    const { ranges, hidden } = render(doc, { anchor: 3 });
    expect(ranges.filter(range => range.widget).map(range => range.from)).toEqual([13]);
    expect(hidden.map(range => range.from)).toEqual([11]);
});

test("numbered tasks keep their number", () => {
    const doc = "1. [ ] first\n\ntext";
    const { ranges, hidden } = render(doc, { anchor: doc.length });
    expect(ranges.filter(range => range.widget).map(range => doc.slice(range.from, range.to))).toEqual(["[ ]"]);
    expect(hidden).toEqual([]);
});

test("quotes are marked per line and hide the marker until edited", () => {
    const doc = "> first\n> second\n\ntext";
    const { ranges, hidden } = render(doc, { anchor: doc.length });
    expect(ranges.filter(range => range.class === "md-quote").map(range => range.from)).toEqual([0, 8]);
    expect(hidden.map(range => doc.slice(range.from, range.to))).toEqual(["> ", "> "]);
    expect(render(doc, { anchor: 3 }).hidden.map(range => range.from)).toEqual([8]);
    expect(render(">tight\n\ntext", { anchor: 12 }).hidden).toEqual([{ from: 0, to: 1 }]);
});

test("a bracketed word is not a link unless a reference defines it", () => {
    const linked = doc => render(doc, { anchor: doc.length }, false).ranges.filter(range => range.class === "md-link").map(range => doc.slice(range.from, range.to));
    expect(linked("A [x] word and [[Plan]].")).toEqual([]);
    expect(linked("[a](https://a.test) and [b][]\n\n[b]: https://b.test")).toEqual(["[a](https://a.test)", "[b][]"]);
    expect(linked("[Shortcut] and [text][Ref]\n\n[shortcut]: /s\n[ref]: /r")).toEqual(["[Shortcut]", "[text][Ref]"]);
    // An undefined reference keeps its brackets.
    expect(render("[x][missing]", { anchor: 0 }, false).hidden).toEqual([]);
});

function wikiState(doc, selection, answers = []) {
    return EditorState.create({
        doc, selection,
        extensions: [markdown({ base: commonmarkLanguage, extensions: [TaskList] }), wikiLinkField],
    }).update({ effects: setResolved.of(answers) }).state;
}
function wikiRender(state, focused) {
    const ranges = [];
    for (let cursor = decorations(state, focused).iter(); cursor.value; cursor.next()) {
        ranges.push({ from: cursor.from, to: cursor.to, ...cursor.value.spec });
    }
    return ranges;
}

test("wiki links are found outside code, links, images and escapes", () => {
    const doc = "[[Plan]] [[a|label]] `[[code]]` \\[[escaped]] [[x]](https://x.test) ![[[img]]](i.png) [[]]\n```\n[[fenced]]\n```\n<b title=\"[[html]]\">";
    const state = wikiState(doc, { anchor: 0 });
    expect(wikiLinks(state).map(link => [link.target, link.label])).toEqual([["Plan", null], ["a", "label"]]);
});

test("a resolved wiki link shows its title until the cursor enters it; an unresolved one is plain", () => {
    const doc = "See [[p1]] and [[p2|our plan]] and [[gone]].";
    const answers = [["p1", { title: "Plan", href: "/p/1" }], ["p2", { title: "Brief", href: "/p/2" }], ["gone", null]];
    const shown = state => wikiRender(state, true).filter(range => range.widget).map(range => [doc.slice(range.from, range.to), range.widget.text, range.widget.href]);
    const away = wikiState(doc, { anchor: 0 }, answers);
    expect(shown(away)).toEqual([["[[p1]]", "Plan", "/p/1"], ["[[p2|our plan]]", "our plan", "/p/2"]]);
    expect(wikiRender(away, true).some(range => range.class === "md-link" && doc.slice(range.from, range.to) === "[[gone]]")).toBe(false);
    // The cursor at an edge still shows the title; inside, the source, marked as a link.
    expect(shown(wikiState(doc, { anchor: 10 }, answers))).toHaveLength(2);
    const inside = wikiState(doc, { anchor: 7 }, answers);
    expect(shown(inside).map(item => item[0])).toEqual(["[[p2|our plan]]"]);
    expect(wikiRender(inside, true).some(range => range.class === "md-link" && range.from === 4 && range.to === 10)).toBe(true);
    // Without focus every resolved link shows its title.
    expect(wikiRender(inside, false).filter(range => range.widget)).toHaveLength(2);
    // No answer yet: plain text.
    expect(wikiRender(wikiState(doc, { anchor: 0 }), false).filter(range => range.widget)).toEqual([]);
});

test("a wiki link hides formatting inside its source while shown", () => {
    const doc = "[[**bold** title]]";
    const ranges = wikiRender(wikiState(doc, { anchor: 0 }, [["**bold** title", { title: "T", href: "" }]]), false);
    expect(ranges.map(range => range.widget ? "widget" : range.class ?? "hidden")).toEqual(["widget"]);
});
