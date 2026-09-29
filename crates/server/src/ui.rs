//! Leptos integration.
//!
//! Mounts the application's routes, its server functions and the static asset directory
//! into the shared router. `provide_context` hands `Services` to every server-function
//! call, which is how `crates/ui` reaches the engines without depending on HTTP.

use axum::Router;
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};

use crate::router::AppState;

/// Provide the request-scoped context every render and server-function call needs.
///
/// `Services` for the engines, plus the effective scheme the security-header middleware
/// resolved. The renderer cannot see the connection, but the cookie it emits has to agree
/// with the middleware's HSTS decision about whether the request was secure.
fn provide_request_context(services: secreton_engines::Services) {
    let scheme = use_context::<axum::http::request::Parts>().and_then(|parts| {
        parts
            .extensions
            .get::<secreton_domain::proxy::ResolvedScheme>()
            .copied()
    });
    provide_context(services);
    if let Some(scheme) = scheme {
        provide_context(scheme);
    }
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let leptos_options = state.leptos_options.clone();
    let routes = generate_route_list(secreton_ui::App);
    let services = state.services.clone();

    Router::new()
        .leptos_routes_with_context(
            state,
            routes,
            {
                // Runs per request, before the component tree. Server functions call
                // `use_context::<Services>()`; providing it here means a missing service
                // is impossible rather than a runtime `None`. The effective scheme is
                // re-published from the request extensions the security-header middleware
                // filled, so the renderer reads the same decision that middleware makes.
                let services = services.clone();
                move || provide_request_context(services.clone())
            },
            {
                let options = leptos_options.clone();
                move || secreton_ui::app::shell(options.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler_with_context::<
            AppState,
            _,
        >(
            {
                let services = services.clone();
                move || provide_request_context(services.clone())
            },
            {
                let options = leptos_options.clone();
                move |_| secreton_ui::app::shell(options.clone())
            },
        ))
}
