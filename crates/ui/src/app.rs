//! Application shell and routing.

use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{ParentRoute, Route, Router, Routes};
use leptos_router::{StaticSegment, path};

use crate::auth::{provide_session, use_session};
use crate::components::Layout;
use crate::pages::{dashboard::Dashboard, login::Login, not_found::NotFound};

/// The HTML document. Rendered on the server, hydrated in the browser.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                // Without a declared icon every page logs a 404 for /favicon.ico, which
                // looks like a broken asset on every visit.
                <link rel="icon" href="/favicon.svg" type="image/svg+xml"/>
                <Csp/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body class="bg-slate-50 text-slate-900 antialiased">
                <App/>
            </body>
        </html>
    }
}

/// Names the nonce Leptos stamps onto the inline `<script>` tags it emits here, so the
/// security-header middleware can build a policy that authorises exactly those scripts.
///
/// This has to happen inside the render: the nonce is generated per response by Leptos and
/// only the renderer knows it. It is echoed under
/// [`secreton_domain::csp::RENDERED_NONCE_HEADER`], a private header the middleware reads
/// and removes, so the client never sees it and nothing downstream can choose a policy.
/// Without a matching nonce the browser refuses every inline script on the page —
/// including `HydrationScripts`, which boots the WASM bundle — so the page renders but
/// never becomes interactive.
///
/// Only the server has a response to attach a header to, hence the `ssr` gate; in the
/// browser this component is a no-op.
#[component]
fn Csp() -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        if let Some(nonce) = leptos::nonce::use_nonce()
            && let Some(options) = use_context::<leptos_axum::ResponseOptions>()
        {
            options.insert_header(
                axum::http::HeaderName::from_static(secreton_domain::csp::RENDERED_NONCE_HEADER),
                axum::http::HeaderValue::from_str(&nonce).expect("a nonce is a valid header value"),
            );
        }
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_session();

    view! {
        // Tailwind is compiled locally by cargo-leptos into this file. It used to be
        // fetched from cdn.tailwindcss.com at runtime: a build tool never meant for
        // production, and a third-party script with full DOM access on pages that
        // render secrets.
        <Stylesheet id="leptos" href="/pkg/secreton.css"/>
        <Title text="Secreton"/>

        <Router>
            <Routes fallback=NotFound>
                <Route path=StaticSegment("login") view=Login/>
                <ParentRoute path=path!("/") view=Protected>
                    <Route path=path!("") view=Dashboard/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}

/// Gate for routes that need a session.
///
/// This is a convenience for the visitor, not a security boundary: the real check is
/// server-side, in the auth middleware and in every server function. A page that relied on
/// this alone would be bypassable by calling the endpoint directly.
#[component]
fn Protected() -> impl IntoView {
    use leptos_router::components::{Outlet, Redirect};

    let session = use_session();

    view! {
        // The session resource is read inside this boundary; reading it outside one warns
        // in hydrate mode. The boundary sits here, not around the router, because a
        // boundary above the router suppresses routing on the server.
        <Suspense fallback=|| view! {
            <div class="flex h-screen items-center justify-center text-slate-500">"Loading…"</div>
        }>
            {move || {
                if session.is_authenticated() {
                    view! { <Layout><Outlet/></Layout> }.into_any()
                } else {
                    view! { <Redirect path="/login"/> }.into_any()
                }
            }}
        </Suspense>
    }
}
