//! Relay networking shared by the deadhop services: proxy addresses and
//! tunnels, a websocket transport that routes each relay its own way, a relay
//! pool that returns as soon as one relay accepts an event, and classifiers
//! for the hosts relays and proxies live on. Moved verbatim from deadhop's
//! server, which re-exports everything at its old paths.

pub mod error;
pub mod hosts;
pub mod relay;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// Characters allowed in a memo. Besides control characters this refuses the
/// invisible and direction-changing ones, which could be used to make a note
/// shown on the merchant's page read as something else.
pub fn is_plain_text(c: char) -> bool {
    !(c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{FEFF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202F}'
            | '\u{2060}'..='\u{206F}'
            | '\u{E000}'..='\u{F8FF}'
            | '\u{FFF0}'..='\u{FFFF}'
            | '\u{E0000}'..='\u{E0FFF}'
            | '\u{F0000}'..='\u{10FFFF}'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_has_no_control_invisible_or_direction_characters() {
        for ok in ['a', 'é', '日', ' ', '€', '😀'] {
            assert!(is_plain_text(ok), "{ok:?}");
        }
        let hidden = [
            '\n',
            '\u{0}',
            '\u{7f}',
            '\u{ad}',
            '\u{61c}',
            '\u{180e}',
            '\u{feff}',
            '\u{200b}',
            '\u{200f}',
            '\u{2028}',
            '\u{202e}',
            '\u{2060}',
            '\u{206f}',
            '\u{e000}',
            '\u{f8ff}',
            '\u{fff0}',
            '\u{ffff}',
            '\u{e0001}',
            '\u{e0fff}',
            '\u{f0000}',
            '\u{10ffff}',
        ];
        for bad in hidden {
            assert!(!is_plain_text(bad), "{bad:?}");
        }
    }
}
