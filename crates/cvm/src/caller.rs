//! Who sent a request, as the Nostr transport established it.

use contextvm_sdk::transport::server::{ClientPubkey, InboundEvent};
use nostr_sdk::Event;
use rmcp::model::Extensions;

/// Who is asking, as established by the transport.
#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// Hex public key that signed the request.
    pub pubkey: Option<String>,
    /// The signed request event itself.
    pub event: Option<Event>,
}

/// Identity of the requester as injected by the Nostr transport.
pub fn caller_from(ext: &Extensions) -> Caller {
    Caller {
        pubkey: ext.get::<ClientPubkey>().map(|p| p.0.clone()),
        event: ext.get::<InboundEvent>().map(|e| e.0.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys, Kind};

    #[test]
    fn the_caller_is_what_the_transport_put_in_the_extensions() {
        let nobody = caller_from(&Extensions::new());
        assert!(nobody.pubkey.is_none() && nobody.event.is_none());

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(crate::CTXVM_KIND), "{}")
            .sign_with_keys(&keys)
            .unwrap();
        let mut ext = Extensions::new();
        ext.insert(ClientPubkey("abc".into()));
        ext.insert(InboundEvent(event.clone()));
        let caller = caller_from(&ext);
        assert_eq!(caller.pubkey.as_deref(), Some("abc"));
        assert_eq!(caller.event.unwrap().id, event.id);
        assert_eq!(crate::CTXVM_KIND, 25910);
    }
}
