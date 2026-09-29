use leptos::prelude::*;

#[component]
pub fn NotFound() -> impl IntoView {
    // On the server, set the status code as well as rendering the page, so a crawler or
    // a monitor sees a 404 rather than a 200 with "not found" in the body.
    #[cfg(feature = "ssr")]
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.set_status(axum::http::StatusCode::NOT_FOUND);
    }

    view! {
        <main class="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
            <p class="text-6xl font-semibold text-slate-300">"404"</p>
            <h1 class="text-xl font-medium text-slate-800">"Page not found"</h1>
            // A standalone navigation control, not a link inside a sentence: the flex parent
            // blockifies it, so WCAG 2.5.8's inline exception does not apply and it must meet
            // the 24px minimum on its own. `py-1.5` on `text-sm` gives a 32px box.
            <a
                href="/"
                class="rounded-md px-3 py-1.5 text-sm text-blue-600 transition-colors hover:bg-blue-50 hover:underline"
            >
                "Back to the dashboard"
            </a>
        </main>
    }
}
