//! The network tools as a router any service merges into its own MCP server:
//! `check_proxy`, `check_relays`, `get_relay_history`, `get_privacy_audit`
//! and `resolve_i2p_name`. The service says who is calling and how errors
//! look on its wire; the runtime and its host do the rest.

use std::future::Future;
use std::pin::Pin;

use deadhop_cvm::caller::Caller;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{Extensions, Tool};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};

use crate::error::Error;
use crate::i2p::I2pNameLookup;
use crate::netruntime::{
    CheckProxyParams, NetworkHost, NetworkRuntime, RelayHealthReport, RelayHistory, RelayHistoryParams,
    ResolveI2pNameParams,
};
use crate::privacy::{PrivacyAudit, ProxyCheck};

/// A service that serves the network tools.
pub trait NetworkServer: Send + Sync + 'static {
    /// Its network runtime.
    fn network(&self) -> &NetworkRuntime;
    /// The host the runtime works for.
    fn host(&self) -> &dyn NetworkHost;
    /// Who sent a request, as the service's transport established it.
    fn caller(&self, ext: &Extensions) -> Caller;
    /// An error as the service shows it to its callers.
    fn to_rpc(&self, e: Error) -> ErrorData;
}

type Reply<'a, T> = Pin<Box<dyn Future<Output = Result<Json<T>, ErrorData>> + Send + 'a>>;

/// A tool's metadata, built the way rmcp's `#[tool]` builds it.
fn tool<P: rmcp::schemars::JsonSchema + 'static, T: rmcp::schemars::JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    Tool::new_with_raw(
        name,
        Some(description.into()),
        rmcp::handler::server::common::schema_for_input::<P>().expect("the parameters have a valid schema"),
    )
    .with_raw_output_schema(
        rmcp::handler::server::tool::schema_for_output::<T>().expect("the result has a valid schema"),
    )
}

/// A tool that takes no arguments.
fn bare<T: rmcp::schemars::JsonSchema + 'static>(name: &'static str, description: &'static str) -> Tool {
    Tool::new_with_raw(
        name,
        Some(description.into()),
        rmcp::handler::server::common::schema_for_empty_input(),
    )
    .with_raw_output_schema(
        rmcp::handler::server::tool::schema_for_output::<T>().expect("the result has a valid schema"),
    )
}

fn resolve_i2p_name<S: NetworkServer>(
    s: &S,
    Parameters(p): Parameters<ResolveI2pNameParams>,
    ctx: RequestContext<RoleServer>,
) -> Reply<'_, I2pNameLookup> {
    let c = s.caller(&ctx.extensions);
    Box::pin(async move {
        s.network()
            .resolve_i2p_name(s.host(), &c, p)
            .await
            .map(Json)
            .map_err(|e| s.to_rpc(e))
    })
}

fn check_proxy<S: NetworkServer>(
    s: &S,
    Parameters(p): Parameters<CheckProxyParams>,
    ctx: RequestContext<RoleServer>,
) -> Reply<'_, ProxyCheck> {
    let c = s.caller(&ctx.extensions);
    Box::pin(async move {
        s.network()
            .check_proxy(s.host(), &c, p)
            .await
            .map(Json)
            .map_err(|e| s.to_rpc(e))
    })
}

fn check_relays<S: NetworkServer>(s: &S, ctx: RequestContext<RoleServer>) -> Reply<'_, RelayHealthReport> {
    let c = s.caller(&ctx.extensions);
    Box::pin(async move {
        s.network()
            .check_relays(s.host(), &c)
            .await
            .map(Json)
            .map_err(|e| s.to_rpc(e))
    })
}

fn get_relay_history<S: NetworkServer>(
    s: &S,
    Parameters(p): Parameters<RelayHistoryParams>,
    ctx: RequestContext<RoleServer>,
) -> Reply<'_, RelayHistory> {
    let c = s.caller(&ctx.extensions);
    Box::pin(async move {
        s.network()
            .relay_history(s.host(), &c, p)
            .map(Json)
            .map_err(|e| s.to_rpc(e))
    })
}

fn get_privacy_audit<S: NetworkServer>(s: &S, ctx: RequestContext<RoleServer>) -> Reply<'_, PrivacyAudit> {
    let c = s.caller(&ctx.extensions);
    Box::pin(async move {
        s.network()
            .privacy_audit(s.host(), &c)
            .await
            .map(Json)
            .map_err(|e| s.to_rpc(e))
    })
}

/// Most serialized bytes of tool descriptions in one page of `tools/list`. A
/// reply travels as one encrypted Nostr event, which cannot be larger than
/// 64 KiB (NIP-44) once it is escaped and wrapped, and oversized transfers are
/// off on the services that use this. The whole list is already above that, so it is paged.
pub const LIST_PAGE_BYTES: usize = 28_000;

/// The tools sorted by name, and the one page that starts at `cursor` (an
/// index, as text), with the cursor of the next page if there is one.
pub fn tool_page(
    mut tools: Vec<rmcp::model::Tool>,
    cursor: Option<&str>,
) -> Result<(Vec<rmcp::model::Tool>, Option<String>), ErrorData> {
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let start = match cursor {
        None => 0,
        Some(c) => c
            .parse::<usize>()
            .ok()
            .filter(|i| *i < tools.len())
            .ok_or_else(|| ErrorData::invalid_params("unknown cursor", None))?,
    };
    let mut bytes = 0;
    let mut end = start;
    while end < tools.len() {
        bytes += serde_json::to_string(&tools[end]).map_or(0, |t| t.len());
        // A page holds at least one tool, however large.
        if end > start && bytes > LIST_PAGE_BYTES {
            break;
        }
        end += 1;
    }
    let next = (end < tools.len()).then(|| end.to_string());
    Ok((tools[start..end].to_vec(), next))
}

/// The network tools, for a service to merge into its own router.
pub fn network_router<S: NetworkServer>() -> ToolRouter<S> {
    ToolRouter::<S>::new()
        .with_route((
            tool::<ResolveI2pNameParams, I2pNameLookup>(
                "resolve_i2p_name",
                "Operators only: look up an I2P name (such as example.i2p) by asking every configured I2P name \
                 registry through the I2P router proxy; returns its .b32.i2p address and which registries agree, \
                 disagree or do not know it.",
            ),
            resolve_i2p_name::<S>,
        ))
        .with_route((
            tool::<CheckProxyParams, ProxyCheck>(
                "check_proxy",
                "Operators only: open a tunnel through a proxy (default: the current one) to each live relay and \
                 report, per relay, whether it worked and why not.",
            ),
            check_proxy::<S>,
        ))
        .with_route((
            bare::<RelayHealthReport>(
                "check_relays",
                "Operators only: check every live relay now: does it connect, does it carry ContextVM events \
                 from one connection to another, and is it rate-limiting us.",
            ),
            check_relays::<S>,
        ))
        .with_route((
            tool::<RelayHistoryParams, RelayHistory>(
                "get_relay_history",
                "Operators only: how each relay did over a window (15m, 1h, 12h, 1d or 1w): health checks and \
                 replies sent, how many failed, and a series of buckets to plot.",
            ),
            get_relay_history::<S>,
        ))
        .with_route((
            bare::<PrivacyAudit>(
                "get_privacy_audit",
                "Operators only: what can be learned about where this service runs, scored from the checks it \
                 can make.",
            ),
            get_privacy_audit::<S>,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: String, size: usize) -> Tool {
        Tool::new_with_raw(
            name,
            Some("x".repeat(size).into()),
            rmcp::handler::server::common::schema_for_empty_input(),
        )
    }

    #[test]
    fn the_tool_list_is_paged_so_no_reply_outgrows_an_event() {
        let all: Vec<Tool> = (0..12).rev().map(|i| named(format!("t{i:02}"), 6_000)).collect();
        let mut names: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let (tools, next) = tool_page(all.clone(), cursor.as_deref()).unwrap();
            let size = serde_json::to_string(&tools).unwrap().len();
            assert!(size <= LIST_PAGE_BYTES + 7_000, "a page of {size} bytes");
            names.extend(tools.iter().map(|t| t.name.to_string()));
            pages += 1;
            match next {
                Some(n) => cursor = Some(n),
                None => break,
            }
        }
        assert!(pages >= 2, "{pages}");
        let expected: Vec<String> = (0..12).map(|i| format!("t{i:02}")).collect();
        assert_eq!(names, expected, "every tool exactly once, in order");
        for bad in ["x", "-1", "99", "12"] {
            assert!(tool_page(all.clone(), Some(bad)).is_err(), "{bad}");
        }
        // One tool bigger than a page still gets a page of its own.
        let (one, next) = tool_page(vec![named("big".into(), 40_000), named("small".into(), 1)], None).unwrap();
        assert_eq!((one.len(), next.as_deref()), (1, Some("1")));
    }
}
