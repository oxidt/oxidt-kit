//! Shared locale contract for authentication UI and transactional emails.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    #[default]
    En,
    De,
}
impl Locale {
    pub fn code(self) -> &'static str {
        self.pick("en", "de")
    }
    pub fn pick<'a>(self, en: &'a str, de: &'a str) -> &'a str {
        match self {
            Self::En => en,
            Self::De => de,
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value.split('-').next()?.to_ascii_lowercase().as_str() {
            "en" => Some(Self::En),
            "de" => Some(Self::De),
            _ => None,
        }
    }
    /// Explicit preference wins; otherwise choose the highest supported language quality.
    pub fn negotiate(cookie: &str, accept_language: &str) -> Self {
        if let Some(locale) = cookie
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find_map(|(key, value)| {
                (key == "oxidt_locale")
                    .then(|| Self::parse(value))
                    .flatten()
            })
        {
            return locale;
        }
        let mut best = (0.0_f32, Self::En);
        for language in accept_language.split(',') {
            let mut parts = language.trim().split(';');
            let locale = parts.next().and_then(Self::parse);
            let quality = parts
                .find_map(|part| part.trim().strip_prefix("q="))
                .map_or(1.0, |q| q.parse::<f32>().unwrap_or(0.0));
            if let Some(locale) = locale
                && quality > best.0
                && quality <= 1.0
            {
                best = (quality, locale);
            }
        }
        best.1
    }
    #[cfg(feature = "server")]
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        Self::negotiate(
            headers
                .get("cookie")
                .and_then(|h| h.to_str().ok())
                .unwrap_or(""),
            headers
                .get("accept-language")
                .and_then(|h| h.to_str().ok())
                .unwrap_or(""),
        )
    }
}
#[cfg(any(feature = "server", feature = "web"))]
pub fn current() -> Locale {
    use dioxus::prelude::*;
    try_consume_context::<Signal<Locale>>()
        .map(|locale| *locale.read())
        .unwrap_or_default()
}
#[cfg(any(feature = "server", feature = "web"))]
pub fn tr(text: &str) -> String {
    if current() == Locale::En {
        return text.to_owned();
    }
    static CATALOG: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
        std::sync::OnceLock::new();
    CATALOG
        .get_or_init(|| {
            serde_json::from_str(include_str!("../locales/de.json")).expect("valid German catalog")
        })
        .get(text)
        .cloned()
        .unwrap_or_else(|| text.to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_and_quality() {
        assert_eq!(Locale::negotiate("oxidt_locale=de", "en"), Locale::De);
        assert_eq!(
            Locale::negotiate("oxidt_locale=bad", "fr, de-DE;q=0.8,en;q=0.5"),
            Locale::De
        );
        assert_eq!(Locale::negotiate("", "de;q=0,en;q=0.8"), Locale::En);
        assert_eq!(Locale::negotiate("", "de;q=NaN"), Locale::En);
    }
}
