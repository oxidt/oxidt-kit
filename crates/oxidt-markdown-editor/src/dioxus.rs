//! Controlled Dioxus component. The custom element owns browser lifecycle;
//! Rust supplies the value and receives standard textarea input events.

use ::dioxus::prelude::*;

const EDITOR_JS: Asset = asset!("/assets/markdown-editor.js");

#[component]
pub fn MarkdownEditor(
    id: String,
    value: String,
    oninput: EventHandler<String>,
    #[props(default = "Markdown".into())] label: String,
    #[props(default = "Write in Markdown…".into())] placeholder: String,
    #[props(default)] name: String,
    #[props(default)] disabled: bool,
    #[props(default)] required: bool,
    #[props(default)] maxlength: Option<usize>,
) -> Element {
    // A value attribute is ignored on a textarea, so server-rendered HTML
    // carries the first value as content: the no-JS fallback and form reset.
    let initial = use_hook(|| textarea_content(&value));
    rsx! {
        document::Script { r#type: "module", src: EDITOR_JS }
        oxidt-markdown-editor {
            div { "data-editor-host": "" }
            textarea {
                id, name, value, placeholder, disabled, required,
                dangerous_inner_html: initial,
                maxlength: maxlength.map(|value| value.to_string()),
                aria_label: label,
                rows: "14",
                oninput: move |event| oninput.call(event.value()),
            }
        }
    }
}

/// Escape textarea content. HTML parsing drops one newline right after
/// `<textarea>`, so a value starting with a newline gets an extra one.
fn textarea_content(value: &str) -> String {
    let mut html = String::with_capacity(value.len() + 1);
    if value.starts_with('\n') {
        html.push('\n');
    }
    for c in value.chars() {
        match c {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            c => html.push(c),
        }
    }
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_render_puts_the_value_in_the_textarea() {
        fn app() -> Element {
            rsx! {
                MarkdownEditor { id: "body", value: "\n# Title\n</textarea><b>&", oninput: |_| {} }
            }
        }
        let mut dom = VirtualDom::new(app);
        dom.rebuild_in_place();
        let html = dioxus_ssr::render(&dom);
        assert!(
            html.contains(">\n\n# Title\n&lt;/textarea&gt;&lt;b&gt;&amp;</textarea>"),
            "{html}"
        );
    }
}
