# oxidt-markdown-editor

A Markdown writing field with live formatting, shared by Topcoat and Dioxus.
Headings, emphasis, links, lists and code blocks render in place. Syntax stays
visible on selected lines and reappears when the cursor returns to a line.
The underlying value is always Markdown. Images and tables remain source text.

Enable only the framework you use. No framework is enabled by default.
Both wrappers bundle the same checked-in JavaScript; consumers do not need Bun.

## Slash commands

Type `/` at the start of an empty line to open the command menu. Keep typing
to filter, use Up/Down and Enter to choose, or click an option. Escape dismisses
the menu and leaves the typed text intact. Commands also stay literal in code
blocks. Inserting a command is one undo step and updates the form value normally.

Commands: `/heading-1`, `/heading-2`, `/heading-3`, `/bullet-list`,
`/numbered-list`, `/task-list`, `/quote`, and `/code`. The code command inserts
a fenced block with the cursor inside it.

## Topcoat

```rust,ignore
use oxidt_markdown_editor::topcoat::markdown_editor;
use topcoat::view::{attributes, view};

view! {
    markdown_editor(
        value: &post.markdown,
        attrs: attributes! {
            id="post-body"
            name="markdown"
            aria-label="Post body"
            placeholder="Write in Markdown…"
        },
    )
}
```

Use Topcoat's usual asset bundling and `.assets(AssetBundle::load()?)` setup.
The component renders a module script with a content-hashed asset URL and an
escaped textarea. Without JavaScript, ordinary form submission still works.
The component needs no Topcoat runtime signals, shards, or WebSocket connection.

## Dioxus

```rust,ignore
use oxidt_markdown_editor::dioxus::MarkdownEditor;

rsx! {
    MarkdownEditor {
        id: "message-body",
        value: body(),
        oninput: move |value| body.set(value),
        label: "Message",
        disabled: busy(),
        required: true,
        maxlength: 100_000,
    }
}
```

`document::Script` loads the module once. Controlled value changes update the
editor without echoing an input event. Removing the component destroys the
CodeMirror view; multiple fields keep independent state and undo histories.

## App integration

The textarea emits bubbling `input` events and keeps its `value` and selection
in sync. Saving, uploads, HTML rendering and application shortcuts remain in
the host app. After mounting, access the field's browser API with:

```js
const editor = textarea.closest("oxidt-markdown-editor").editor;
editor.setValue(markdown);            // emits input if changed
editor.setValue(markdown, false);     // controlled update, no input echo
editor.insert(offset, imageMarkdown); // its own undo step
editor.show(false);                  // hide for a server-rendered preview
editor.show(true);                   // show and focus
```

The API is absent until the module loads; retain the textarea fallback.
`positionAt(event)` maps a drop's client coordinates to a document offset.
Native `required`, `maxlength`, `disabled`, `readonly`, labels and form reset
are supported. Server validation remains the application's responsibility.

Styles use DaisyUI colors when available, with plain CSS fallbacks. Override
`--md-editor-background`, `--md-editor-color`, `--md-editor-border`,
`--md-editor-accent`, `--md-editor-code-background`, or `--md-editor-min-height`
on a parent when the app needs different colors or dimensions.

## Development

From this crate's directory, using Bun 1.3.5:

```sh
bun install --frozen-lockfile
bun run test:editor
bun run build:editor
bunx playwright install chromium
bun run test:browser
```

Commit the generated `assets/markdown-editor.js` alongside its source. The
build preserves third-party license notices. Rust feature checks from the kit:

```sh
cargo check -p oxidt-markdown-editor --no-default-features
cargo check -p oxidt-markdown-editor --features topcoat
cargo check -p oxidt-markdown-editor --features dioxus --target wasm32-unknown-unknown
```
