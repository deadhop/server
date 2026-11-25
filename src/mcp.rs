//! ContextVM surface: strictly typed MCP tools served over Nostr. Five are
//! for invoicing; the rest are operator-only management tools.
//!
//! Inputs are deserialised into `deny_unknown_fields` structs and outputs are
//! serialised from structs with published JSON schemas, so nothing free-form
//! crosses the boundary in either direction.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ErrorCode, Extensions, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use serde_json::json;

use crate::error::Error;
use crate::keys::KeyDef;
use crate::manage::{
    AddOperatorParams, AuditLog, AuditParams, Backup, BackupList, ControlParams, ControlResult, Health, Metrics,
    NetworkView, RemoveOperatorParams, Series, SeriesParams, SettingsView, UpdateNetworkParams, UpdateSettingsParams,
    WipeParams, WipeResult,
};
use crate::service::{
    CreateInvoiceParams, GetInvoiceParams, Info, Invoice, InvoiceList, ListInvoicesParams, Service, Stats,
};

// Reading the requester lives in the ContextVM crate and keeps its old path.
pub use deadhop_cvm::caller::caller_from;

/// Convert a service error into a JSON-RPC error with a stable `data.code`.
pub fn rpc_error(e: Error) -> ErrorData {
    let code = match e.code() {
        "invalid_params" => -32602,
        "unauthorized" => -32001,
        "not_found" => -32002,
        "pow_rejected" => -32003,
        "rate_limited" => -32004,
        "capacity" => -32005,
        "paused" => -32006,
        "unavailable" => -32007,
        _ => {
            tracing::error!(error = %e, "internal error while serving a request");
            -32603
        }
    };
    ErrorData::new(ErrorCode(code), e.public_message(), Some(json!({ "code": e.code() })))
}

/// The MCP server exposed over ContextVM on one key. What the key may do is
/// fixed by its row in [`crate::keys::KEYS`]: the server lists and serves only
/// those tools, and a key for operators serves nobody else.
#[derive(Clone)]
pub struct PayServer {
    svc: Arc<Service>,
    key: &'static KeyDef,
    router: ToolRouter<PayServer>,
}

impl PayServer {
    /// Every tool: this service's own and the network tools of its engine.
    pub fn tool_router() -> ToolRouter<Self> {
        Self::own_tools() + deadhop_netengine::tools::network_router::<PayServer>()
    }

    pub fn new(svc: Arc<Service>, key: &'static KeyDef) -> Self {
        let mut router = Self::tool_router();
        if let Some(allowed) = key.tools {
            for tool in router.list_all() {
                if !allowed.contains(&tool.name.as_ref()) {
                    router.remove_route(&tool.name);
                }
            }
        }
        PayServer { svc, key, router }
    }

    /// Refuse anyone but an operator on a key that is for operators only.
    fn gate(&self, ext: &Extensions) -> Result<(), ErrorData> {
        if self.key.operators_only {
            self.svc.require_admin(&caller_from(ext)).map_err(rpc_error)?;
        }
        Ok(())
    }
}

#[tool_router(router = own_tools)]
impl PayServer {
    #[tool(
        name = "get_info",
        description = "Service parameters: network, limits, required proof of work, and whether the caller is an operator."
    )]
    async fn tool_get_info(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Info>, ErrorData> {
        self.svc
            .info(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "create_invoice",
        description = "Create an on-chain invoice with a fresh address. Non-operators must mine NIP-13 proof of work into the request event."
    )]
    async fn tool_create_invoice(
        &self,
        Parameters(p): Parameters<CreateInvoiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Invoice>, ErrorData> {
        self.svc
            .create_invoice(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_invoice",
        description = "Look up an invoice and its payment status by id."
    )]
    async fn tool_get_invoice(
        &self,
        Parameters(p): Parameters<GetInvoiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Invoice>, ErrorData> {
        self.svc
            .get_invoice(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "list_invoices",
        description = "Operators only: page through invoices, newest first."
    )]
    async fn tool_list_invoices(
        &self,
        Parameters(p): Parameters<ListInvoicesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<InvoiceList>, ErrorData> {
        self.svc
            .list_invoices(&caller_from(&ctx.extensions), p)
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_stats",
        description = "Operators only: totals per status and chain backend health."
    )]
    async fn tool_get_stats(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Stats>, ErrorData> {
        self.svc
            .stats(&caller_from(&ctx.extensions))
            .map(Json)
            .map_err(rpc_error)
    }

    #[tool(
        name = "get_health",
        description = "Operators only: relay connections, chain backend, database integrity and process uptime."
    )]
    async fn tool_get_health(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Health>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.health(&c).await.map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "get_metrics",
        description = "Operators only: addresses created, invoices, payments and payments within 24h, 7d, 30d and 365d."
    )]
    async fn tool_get_metrics(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Metrics>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.metrics(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "get_payment_series",
        description = "Operators only: confirmed payments per hour, day or week for a line chart."
    )]
    async fn tool_get_payment_series(
        &self,
        Parameters(p): Parameters<SeriesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Series>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.payment_series(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "get_settings",
        description = "Operators only: live settings, environment defaults, overrides and operator keys."
    )]
    async fn tool_get_settings(&self, ctx: RequestContext<RoleServer>) -> Result<Json<SettingsView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.get_settings(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "update_settings",
        description = "Operators only: change settings at runtime. A new relay list restarts the relay connections."
    )]
    async fn tool_update_settings(
        &self,
        Parameters(p): Parameters<UpdateSettingsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<SettingsView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.update_settings(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "reset_settings",
        description = "Operators only: forget settings changed from the dashboard and use the environment values."
    )]
    async fn tool_reset_settings(&self, ctx: RequestContext<RoleServer>) -> Result<Json<SettingsView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.reset_settings(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "add_operator",
        description = "Operators only: let another Nostr key (hex, npub or nprofile) operate the service."
    )]
    async fn tool_add_operator(
        &self,
        Parameters(p): Parameters<AddOperatorParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<SettingsView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.add_operator(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "remove_operator",
        description = "Operators only: revoke an operator key added from the dashboard."
    )]
    async fn tool_remove_operator(
        &self,
        Parameters(p): Parameters<RemoveOperatorParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<SettingsView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.remove_operator(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "control_service",
        description = "Operators only: stop or start invoicing, or restart the relay connections."
    )]
    async fn tool_control_service(
        &self,
        Parameters(p): Parameters<ControlParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<ControlResult>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.control(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "backup_database",
        description = "Operators only: write a consistent backup of the database on the service host."
    )]
    async fn tool_backup_database(&self, ctx: RequestContext<RoleServer>) -> Result<Json<Backup>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.backup(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "list_backups",
        description = "Operators only: the database backups kept on the service host, newest first."
    )]
    async fn tool_list_backups(&self, ctx: RequestContext<RoleServer>) -> Result<Json<BackupList>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.list_backups(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "wipe_database",
        description = "Operators only: delete every invoice after taking a backup. Requires confirm = WIPE."
    )]
    async fn tool_wipe_database(
        &self,
        Parameters(p): Parameters<WipeParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<WipeResult>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.wipe(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "get_network",
        description = "Operators only: the network settings (relays, which keys use them, relay names, proxies, routing rules, I2P registries) with their environment defaults, the keys they are assigned to and the bitcoin network."
    )]
    async fn tool_get_network(&self, ctx: RequestContext<RoleServer>) -> Result<Json<NetworkView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.get_network(&c).map(Json).map_err(rpc_error)
    }

    #[tool(
        name = "update_network",
        description = "Operators only: change the network settings; anything left out stays as it is. Checked, stored and applied exactly like update_settings."
    )]
    async fn tool_update_network(
        &self,
        Parameters(p): Parameters<UpdateNetworkParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<NetworkView>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.update_network(&c, p).map(Json).map_err(rpc_error)
    }

    #[tool(name = "get_audit_log", description = "Operators only: recent operator actions.")]
    async fn tool_get_audit_log(
        &self,
        Parameters(p): Parameters<AuditParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<AuditLog>, ErrorData> {
        let c = caller_from(&ctx.extensions);
        self.svc.audit_log(&c, p).map(Json).map_err(rpc_error)
    }
}

pub use deadhop_netengine::tools::{tool_page, LIST_PAGE_BYTES};

#[tool_handler(router = self.router)]
impl ServerHandler for PayServer {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        self.gate(&context.extensions)?;
        self.router.call(ToolCallContext::new(self, request, context)).await
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, ErrorData> {
        self.gate(&context.extensions)?;
        tool_page(self.router.list_all(), request.and_then(|r| r.cursor).as_deref()).map(|(tools, next_cursor)| {
            rmcp::model::ListToolsResult {
                tools,
                meta: None,
                next_cursor,
            }
        })
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("deadhop", env!("CARGO_PKG_VERSION")))
            .with_instructions("On-chain bitcoin invoices over ContextVM.")
    }
}

impl deadhop_netengine::tools::NetworkServer for PayServer {
    fn network(&self) -> &crate::netruntime::NetworkRuntime {
        &self.svc.net
    }

    fn host(&self) -> &dyn crate::netruntime::NetworkHost {
        &*self.svc
    }

    fn caller(&self, ext: &Extensions) -> crate::service::Caller {
        caller_from(ext)
    }

    fn to_rpc(&self, e: deadhop_netengine::error::Error) -> ErrorData {
        rpc_error(e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextvm_sdk::transport::server::{ClientPubkey, InboundEvent};
    use nostr_sdk::{EventBuilder, Keys, Kind};

    #[test]
    fn the_tool_list_is_paged_so_no_reply_outgrows_an_event() {
        let all = PayServer::tool_router().list_all();
        let mut names: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let (tools, next) = tool_page(all.clone(), cursor.as_deref()).unwrap();
            let size = serde_json::to_string(&tools).unwrap().len();
            assert!(size <= LIST_PAGE_BYTES + 15_000, "a page of {size} bytes");
            names.extend(tools.iter().map(|t| t.name.to_string()));
            pages += 1;
            match next {
                Some(n) => cursor = Some(n),
                None => break,
            }
        }
        assert!(pages >= 2, "the whole list is too big for one reply");
        let mut expected: Vec<String> = all.iter().map(|t| t.name.to_string()).collect();
        expected.sort();
        assert_eq!(names, expected, "every tool exactly once, in order");
        let past_end = all.len().to_string();
        for bad in ["x", "-1", "99", past_end.as_str()] {
            assert!(tool_page(all.clone(), Some(bad)).is_err(), "{bad}");
        }
        // One tool bigger than a page still gets a page of its own.
        let (one, _) = tool_page(all.clone(), Some("0")).unwrap();
        assert!(!one.is_empty());
    }

    #[test]
    fn caller_is_read_from_extensions() {
        let empty = caller_from(&Extensions::new());
        assert!(empty.pubkey.is_none() && empty.event.is_none());

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(25910), "{}")
            .sign_with_keys(&keys)
            .unwrap();
        let mut ext = Extensions::new();
        ext.insert(ClientPubkey("abc".into()));
        ext.insert(InboundEvent(event.clone()));
        let c = caller_from(&ext);
        assert_eq!(c.pubkey.as_deref(), Some("abc"));
        assert_eq!(c.event.unwrap().id, event.id);
    }

    #[test]
    fn errors_map_to_stable_codes_without_leaking_internals() {
        let cases = [
            (Error::InvalidParams("bad".into()), -32602, "invalid_params"),
            (Error::Unauthorized, -32001, "unauthorized"),
            (Error::NotFound, -32002, "not_found"),
            (Error::Pow("weak".into()), -32003, "pow_rejected"),
            (Error::RateLimited, -32004, "rate_limited"),
            (Error::Capacity, -32005, "capacity"),
            (Error::Paused, -32006, "paused"),
            (Error::Unavailable, -32007, "unavailable"),
            (Error::Chain("10.1.2.3:50001 refused".into()), -32603, "internal"),
        ];
        for (err, code, name) in cases {
            let e = rpc_error(err);
            assert_eq!(e.code.0, code);
            assert_eq!(e.data.unwrap()["code"], name);
            assert!(!e.message.contains("10.1.2.3"));
        }
    }

    /// `check_proxy` and the other network tools open connections from this
    /// machine: a key anyone may use must never serve them, whatever a future
    /// row in `KEYS` says about its tools.
    #[tokio::test]
    async fn no_public_key_serves_a_network_tool() {
        let r = crate::service::tests::rig(|_| {}).await;
        let network: Vec<String> = deadhop_netengine::tools::network_router::<PayServer>()
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(network.len() >= 5, "{network:?}");
        assert!(network.iter().any(|n| n == "check_proxy"));
        let mut public = 0;
        for key in crate::keys::KEYS.iter().filter(|k| !k.operators_only) {
            public += 1;
            let served: Vec<String> = PayServer::new(r.svc.clone(), key)
                .router
                .list_all()
                .iter()
                .map(|t| t.name.to_string())
                .collect();
            for tool in &network {
                assert!(!served.contains(tool), "the public key {:?} serves {tool}", key.id);
            }
        }
        assert!(public > 0, "the table has a public key to check");
    }

    #[test]
    fn tools_list_snapshot() {
        let mut tools = serde_json::to_value(PayServer::tool_router().list_all()).unwrap();
        tools
            .as_array_mut()
            .unwrap()
            .sort_by_key(|t| t["name"].as_str().unwrap().to_string());
        crate::snapshot::check("tools_list", &tools);
    }
}
