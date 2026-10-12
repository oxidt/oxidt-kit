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
    rsx! {
        document::Script { r#type: "module", src: EDITOR_JS }
        oxidt-markdown-editor { "data-value": value.clone(),
            div { "data-editor-host": "" }
            textarea {
                id, name, value, placeholder, disabled, required,
                maxlength: maxlength.map(|value| value.to_string()),
                aria_label: label,
                rows: "14",
                oninput: move |event| oninput.call(event.value()),
            }
        }
    }
}
