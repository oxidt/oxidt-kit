//! Topcoat component using the application's normal asset bundle.

use ::topcoat::{
    Result,
    asset::{Asset, asset},
    view::{Attributes, View, component, view},
};

const EDITOR_JS: Asset = asset!("../assets/markdown-editor.js");

/// Render an ordinary textarea enhanced with live Markdown formatting.
///
/// Forward the input's `id`, `name`, `aria-label`, validation and fallback
/// styling through `attrs`. Values are escaped by `view!`. Module scripts
/// execute once even when several editors appear on the same page.
#[component]
pub async fn markdown_editor(value: &str, #[default] attrs: Attributes) -> Result<impl View> {
    Ok(view! {
        <oxidt-markdown-editor>
            <div data-editor-host=""></div>
            <textarea (attrs)>(value)</textarea>
        </oxidt-markdown-editor>
        <script type="module" src=(EDITOR_JS)></script>
    })
}
