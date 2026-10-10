pub mod alerts;
pub mod arp;
pub mod audit;
pub mod auth;
pub mod dashboard;
pub mod hosts;
pub mod jobs;
pub mod netguard;
pub mod notifications;
pub mod optimize;
pub mod passkey;
pub mod qos;
pub mod results;
pub mod scans;
pub mod signatures;
pub mod version;
pub mod vmqos;
pub mod vms;

use axum::{Router, middleware, routing::{get, post, put}};
use std::sync::Arc;
use crate::AppState;

pub fn routes(state: Arc<AppState>) -> Router {
    // 公开路由
    let public = Router::new()
        .route("/auth/check", get(auth::check_auth))
        .route("/auth/setup", post(auth::setup))
        .route("/auth/login", post(auth::login))
        .route("/auth/verify-totp", post(auth::verify_totp))
        .route("/auth/logout", post(auth::logout))
        .route("/passkey/login/start", post(passkey::login_start))
        .route("/passkey/login/finish", post(passkey::login_finish))
        .route("/passkey/has", post(passkey::has_passkey))
        .route("/version", get(version::current))
        // vmqos 节点面端点（契约 schema v2，token 鉴权，不走管理员会话）
        .route("/v1/vmqos/snapshot", get(vmqos::snapshot))
        .route("/v1/vmqos/qos", get(vmqos::qos_entry).post(vmqos::qos_entry))
        .route("/v1/vmqos/qos/", get(vmqos::qos_entry).post(vmqos::qos_entry))
        .route("/v1/vmqos/intl", get(vmqos::intl_entry).post(vmqos::intl_entry))
        .with_state(state.clone());

    // 需要认证的路由
    let protected = Router::new()
        .route("/hosts", get(hosts::list).post(hosts::create))
        .route("/hosts/{id}", get(hosts::get).put(hosts::update).delete(hosts::delete))
        .route("/hosts/{id}/test", post(hosts::test_connection))
        .route("/hosts/{id}/deploy", post(hosts::deploy))
        .route("/hosts/{id}/scan-vm", post(hosts::scan_vm))
        .route("/hosts/{id}/hostkey/scan", post(hosts::hostkey_scan))
        .route("/hosts/{id}/hostkey/confirm", post(hosts::hostkey_confirm))
        .route("/hosts/{id}/probe", post(hosts::probe))
        .route("/hosts/{id}/components", get(hosts::components))
        .route("/hosts/{id}/vms", get(vms::list))
        .route("/hosts/{id}/vms/sync", post(vms::sync))
        .route("/hosts/{id}/vm-events", get(vms::events))
        .route("/hosts/{id}/jobs", post(jobs::create_on_host))
        .route("/jobs", get(jobs::list))
        .route("/jobs/{id}", get(jobs::get))
        .route("/jobs/{id}/retry", post(jobs::retry))
        .route("/audit", get(audit::list))
        .route("/dashboard", get(dashboard::overview))
        .route("/netguard/ports", get(netguard::list_ports).post(netguard::create_port))
        .route("/netguard/ports/{id}", axum::routing::delete(netguard::delete_port))
        .route("/netguard/ports/{id}/toggle", post(netguard::toggle_port))
        .route("/netguard/domains", get(netguard::list_domains).post(netguard::create_domain))
        .route("/netguard/domains/import", post(netguard::import_domains))
        .route("/netguard/domains/{id}", axum::routing::delete(netguard::delete_domain))
        .route("/netguard/domains/{id}/toggle", post(netguard::toggle_domain))
        .route("/netguard/scope", get(netguard::get_scope).post(netguard::set_scope))
        .route("/netguard/whitelist", post(netguard::add_whitelist))
        .route("/netguard/whitelist/{id}", axum::routing::delete(netguard::del_whitelist))
        .route("/netguard/deploy", post(netguard::deploy))
        .route("/netguard/status", get(netguard::status))
        .route("/netguard/logs/{host_id}", post(netguard::logs))
        .route("/netguard/log-enabled", get(netguard::get_log_enabled).post(netguard::set_log_enabled))
        .route("/arp/modes", get(arp::list_modes))
        .route("/arp/mode/{host_id}", post(arp::set_mode))
        .route("/arp/uninstall/{host_id}", post(arp::uninstall))
        .route("/arp/sync/{host_id}", post(arp::sync))
        .route("/arp/whitelist", post(arp::whitelist_add))
        .route("/arp/whitelist/{id}", axum::routing::delete(arp::whitelist_del))
        .route("/arp/whitelist/{host_id}/list", get(arp::whitelist_list))
        .route("/arp/maps", post(arp::map_add))
        .route("/arp/maps/import", post(arp::map_import))
        .route("/arp/maps/{id}", axum::routing::delete(arp::map_del))
        .route("/arp/maps/{host_id}/list", get(arp::map_list))
        .route("/arp/stats/{host_id}", get(arp::stats_list).post(arp::stats_collect))
        .route("/optimize/init/{host_id}", post(optimize::init))
        .route("/optimize/upgrade/{host_id}", post(optimize::upgrade))
        .route("/optimize/batch", post(optimize::batch))
        .route("/optimize/tune/{host_id}", post(optimize::tune))
        .route("/optimize/rollback/{host_id}", post(optimize::rollback))
        .route("/optimize/status/{host_id}", post(optimize::status).get(optimize::latest_status))
        .route("/qos/templates", get(qos::list_templates).post(qos::create_template))
        .route("/qos/templates/{id}", axum::routing::delete(qos::delete_template))
        .route("/qos/template/{host_id}", post(qos::assign_template))
        .route("/qos/policies", get(qos::list_policies).post(qos::create_policy))
        .route("/qos/policies/{id}", axum::routing::delete(qos::delete_policy))
        .route("/qos/policies/{id}/toggle", post(qos::toggle_policy))
        .route("/qos/events", get(qos::list_events))
        .route("/qos/nodes", get(qos::list_nodes))
        .route("/qos/hosts/{id}/token", post(qos::issue_token))
        .route("/qos/hosts/{id}/tokens", get(qos::list_tokens))
        .route("/qos/clusters", get(qos::list_clusters).post(qos::create_cluster))
        .route("/qos/install/{host_id}", post(qos::install))
        .route("/qos/config/{host_id}", post(qos::config_apply))
        .route("/qos/uninstall/{host_id}", post(qos::uninstall))
        .route("/qos/status/{host_id}", post(qos::status))
        .route("/alerts/rules", get(alerts::list_rules).post(alerts::create_rule))
        .route("/alerts/rules/{id}", axum::routing::delete(alerts::delete_rule))
        .route("/alerts/rules/{id}/toggle", post(alerts::toggle_rule))
        .route("/alerts/history", get(alerts::history))
        .route("/inspect/settings", get(alerts::get_inspect_settings).put(alerts::put_inspect_settings))
        .route("/inspect/{host_id}", post(alerts::inspect_now))
        .route("/signatures", get(signatures::list).post(signatures::create))
        .route("/signatures/{id}", axum::routing::delete(signatures::delete))
        .route("/signatures/{id}/toggle", post(signatures::toggle))
        .route("/signatures/push/{host_id}", post(signatures::push))
        .route("/scans", get(scans::list).post(scans::create))
        .route("/scans/{id}", get(scans::get))
        .route("/scans/{id}/stop", post(scans::stop))
        .route("/results", get(results::list))
        .route("/results/stats", get(results::stats))
        .route("/notifications", get(notifications::list).post(notifications::create))
        .route("/notifications/{id}", put(notifications::update))
        .route("/notifications/test", post(notifications::test))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/reset-totp", post(auth::reset_totp))
        .route("/auth/disable-totp", post(auth::disable_totp))
        .route("/passkey/register/start", post(passkey::register_start))
        .route("/passkey/register/finish", post(passkey::register_finish))
        .route("/passkey/delete", post(passkey::delete))
        .route("/version/check", get(version::check))
        .route("/version/changelog", get(version::changelog))
        .route("/version/update", post(version::update))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), crate::auth::auth_middleware));

    public.merge(protected)
}
