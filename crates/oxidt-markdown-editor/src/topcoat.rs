//! Topcoat component using the application's normal asset bundle.

use ::topcoat::{
    Result,
    asset::{Asset, asset},
    context::Cx,
    view::{Attributes, View, component, view},
};

const EDITOR_JS: Asset = asset!("../assets/markdown-editor.js");

/// Render an ordinary textarea enhanced with live Markdown formatting.
///
/// Forward the input's `id`, `name`, `aria-label`, validation and fallback
/// styling through `attrs`. Values are escaped by `view!`. Module scripts
/// execute once even when several editors appear on the same page.
///
/// The host hooks are opt-in attributes on the same `attrs`:
/// `data-completion-triggers='["[["]'` and `data-wiki-links` (see the crate
/// README for their events).
#[component]
pub async fn markdown_editor(
    cx: &Cx,
    value: &str,
    #[default] attrs: Attributes,
) -> Result<impl View> {
    Ok(view! {
        <oxidt-markdown-editor>
            <div data-editor-host=""></div>
            // HTML parsing drops one newline right after `<textarea>`.
            <textarea (attrs)>
                ("\n")
                (value)
            </textarea>
        </oxidt-markdown-editor>
        <script type="module" src=(EDITOR_JS)></script>
    })
}
