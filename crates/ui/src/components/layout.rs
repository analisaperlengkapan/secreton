use leptos::prelude::*;

use crate::api::Logout as LogoutAction;
use crate::auth::use_session;

/// Chrome around every authenticated page.
#[component]
pub fn Layout(children: Children) -> impl IntoView {
    let session = use_session();
    let logout = ServerAction::<LogoutAction>::new();

    Effect::new(move |_| {
        if logout.value().get().is_some() {
            session.refetch();
        }
    });

    view! {
        <div class="min-h-screen">
            <header class="border-b border-slate-200 bg-white">
                <div class="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
                    <a href="/" class="text-lg font-semibold">"Secreton"</a>
                    <div class="flex items-center gap-4">
                        <span class="text-sm text-slate-600">
                            {move || session.user().map(|u| u.display_name.unwrap_or(u.username))}
                        </span>
                        <ActionForm action=logout>
                            <button
                                type="submit"
                                class="rounded-md px-2 py-1.5 text-sm text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
                            >
                                "Sign out"
                            </button>
                        </ActionForm>
                    </div>
                </div>
            </header>
            <main class="mx-auto max-w-6xl px-4 py-8">{children()}</main>
        </div>
    }
}
