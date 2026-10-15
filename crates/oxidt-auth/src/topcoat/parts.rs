//! Pieces both Topcoat login pages render: the inlined-script wrapper, the
//! locale catalog handed to the script, the spinner and the outline icons.

use ::topcoat::{
    Result,
    context::Cx,
    view::{NodeViewParts, PartsWriter, View, component, view},
};

use crate::locale::Locale;

const DE_CATALOG: &str = include_str!("../../locales/de.json");

/// The catalog the page script translates its messages with.
pub(super) fn catalog(locale: Locale) -> &'static str {
    match locale {
        Locale::De => DE_CATALOG,
        Locale::En => "{}",
    }
}

/// Markup written verbatim. Only for compile-time constants of this crate:
/// the scripts and the locale catalog, none of which contains `</`.
pub(super) struct Trusted(pub(super) &'static str);

impl NodeViewParts for Trusted {
    fn into_view_parts(self, _cx: &Cx, parts: &mut PartsWriter<'_>) {
        parts.push_static_str_unescaped(self.0);
    }
}

#[component]
pub(super) async fn spinner() -> Result<impl View> {
    Ok(view! {
        <span data-spinner="" hidden=(true) class="loading loading-spinner loading-sm"></span>
    })
}

pub(super) const CHECK_CIRCLE: &str = "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z";
pub(super) const X_CIRCLE: &str =
    "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z";

/// Inline outline icon (kept local to avoid an icon-crate dep in the auth crate).
#[component]
pub(super) async fn icon(
    d: &'static str,
    class: &'static str,
    stroke_width: &'static str,
) -> Result<impl View> {
    Ok(view! {
        <svg
            xmlns="http://www.w3.org/2000/svg"
            class=(class)
            fill="none"
            viewBox="0 0 24 24"
            stroke-width=(stroke_width)
            stroke="currentColor"
        >
            <path stroke-linecap="round" stroke-linejoin="round" d=(d)></path>
        </svg>
    })
}
