use leptos::prelude::*;
use leptos_router::components::Redirect;

use crate::api::Login as LoginAction;
use crate::auth::use_session;
use crate::components::{Button, Input};

#[component]
pub fn Login() -> impl IntoView {
    let session = use_session();

    // `ServerAction` submits through the generated endpoint and, crucially, works before
    // hydration: the form posts normally if WebAssembly has not loaded yet, so a slow
    // connection or a blocked bundle still gets a usable login.
    let action = ServerAction::<LoginAction>::new();

    let error = move || {
        action.value().get().and_then(|r| r.err()).map(|e| {
            // `ServerFnError`'s `Display` prefixes the message with a bug-tracking label
            // ("error running server function: …"). That is developer scaffolding, not
            // something to put in front of a person who mistyped a password, so only the
            // message itself is shown.
            match e {
                ServerFnError::ServerError(msg) => msg,
                other => other.to_string(),
            }
        })
    };

    // Re-read the session once the action succeeds, so the redirect below fires.
    Effect::new(move |_| {
        if matches!(action.value().get(), Some(Ok(_))) {
            session.refetch();
        }
    });

    view! {
        // The session resource is read here; reading it outside a boundary warns in
        // hydrate mode and can cause a hydration mismatch. The boundary is local to this
        // page rather than wrapping the router, which would swallow the routing itself.
        <Suspense fallback=|| view! {
            <div class="flex h-screen items-center justify-center text-slate-500">"Loading…"</div>
        }>
        <Show when=move || session.is_authenticated() fallback=move || view! {
            <main class="flex min-h-screen items-center justify-center px-4">
                <div class="w-full max-w-sm space-y-6 rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
                    <div class="space-y-1 text-center">
                        <h1 class="text-2xl font-semibold">"Secreton"</h1>
                        <p class="text-sm text-slate-500">"Sign in to continue"</p>
                    </div>

                    <ActionForm action=action attr:class="space-y-4">
                        <Input
                            name="credentials[username]"
                            label="Username"
                            input_type="text"
                            autocomplete="username"
                            required=true
                        />
                        <Input
                            name="credentials[password]"
                            label="Password"
                            input_type="password"
                            autocomplete="current-password"
                            required=true
                        />
                        <Input
                            name="credentials[mfa_code]"
                            label="MFA code"
                            input_type="text"
                            autocomplete="one-time-code"
                            required=false
                        />

                        <Show when=move || error().is_some()>
                            <p role="alert" class="rounded border border-red-200 bg-red-50 p-2 text-sm text-red-700">
                                {move || error().unwrap_or_default()}
                            </p>
                        </Show>

                        <Button loading=Signal::derive(move || action.pending().get())>
                            "Sign in"
                        </Button>
                    </ActionForm>
                </div>
            </main>
        }>
            <Redirect path="/"/>
        </Show>
        </Suspense>
    }
}
