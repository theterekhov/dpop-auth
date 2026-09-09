//! Demo UI: register, login, and authenticated /me profile screen.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::CryptoKeyPair;

use crate::{client::dpop_requests, crypto, storage};

#[derive(Clone)]
pub struct AppState {
    pub key_pair: CryptoKeyPair,
    pub jwk: serde_json::Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CurrentPage {
    Login,
    Register,
    Dashboard,
}

async fn init_state() -> AppState {
    let db = storage::open().await.unwrap();
    let key_pair = match storage::load_key_pair(&db).await.unwrap() {
        Some(kp) => kp,
        None => {
            let kp = crypto::generate_key_pair().await.unwrap();
            storage::save_key_pair(&db, &kp).await.unwrap();
            kp
        }
    };

    let jwk_str = crypto::export_public_jwk(&key_pair.get_public_key())
        .await
        .unwrap();
    let jwk = serde_json::from_str(&jwk_str).unwrap();

    AppState { key_pair, jwk }
}

#[component]
fn RegisterForm(
    state: AppState,
    set_page: WriteSignal<CurrentPage>,
    set_access_token: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (name, set_name) = signal(String::new());
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (status_msg, set_status_msg) = signal(String::new());

    let st = state.clone();

    let on_submit = move |e: web_sys::SubmitEvent| {
        e.prevent_default();

        let current_state = st.clone();
        let n = name.get_untracked();
        let em = email.get_untracked();
        let pw = password.get_untracked();

        spawn_local(async move {
            let payload = serde_json::json!({
                "name": n,
                "kind": "email",
                "value": em,
                "password": pw
            });

            match dpop_requests(
                &current_state.key_pair,
                &current_state.jwk,
                "POST",
                "http://localhost:3000/api/auth/register",
                None,
                Some(&payload.to_string()),
            )
            .await
            {
                Ok(resp) => {
                    if resp.status == 201 {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.text)
                            && let Some(token) = v["access_token"].as_str()
                        {
                            set_access_token.set(Some(token.to_string()));
                            set_page.set(CurrentPage::Dashboard);
                            return;
                        }
                        set_page.set(CurrentPage::Login);
                    } else {
                        set_status_msg.set(format!("Error ({}): {}", resp.status, resp.text));
                    }
                }

                Err(err) => set_status_msg.set(format!("Request error: {err:?}")),
            }
        });
    };

    view! {
        <div style="max-width: 380px; margin: 3rem auto; padding: 1.5rem; border: 1px solid #ddd; border-radius: 8px; font-family: sans-serif;">
            <h2 style="margin-top: 0px;">"Register Account"</h2>
            <form on:submit=on_submit>
                <div style="margin-bottom: 0.8rem;">
                    <label for="name" style="display: block; font-weight: bold; margin-bottom: 0.2rem;">"Name"</label>
                    <input
                        id="name"
                        type="text"
                        style="width: 100%; box-sizing: border-box; padding: 0.4rem;"
                        prop:value=name
                        on:input=move |e| set_name.set(event_target_value(&e))
                        required
                    />
                </div>
                <div style="margin-bottom: 0.8rem;">
                    <label for="email" style="display: block; font-weight: bold; margin-bottom: 0.2rem;">"Email"</label>
                    <input
                        id="email"
                        type="email"
                        style="width: 100%; box-sizing: border-box; padding: 0.4rem;"
                        prop:value=email
                        on:input=move |e| set_email.set(event_target_value(&e))
                        required
                    />
                </div>
                <div style="margin-bottom: 1.2rem;">
                    <label for="password" style="display: block; font-weight: bold; margin-bottom: 0.2rem;">"Password"</label>
                    <input
                        id="password"
                        type="password"
                        style="width: 100%; box-sizing: border-box; padding: 0.4rem;"
                        prop:value=password
                        on:input=move |e| set_password.set(event_target_value(&e))
                        required
                    />
                </div>
                <button type="submit" style="width: 100%; padding: 0.6rem; cursor: pointer;">
                    "Create Account"
                </button>
            </form>

            <p style="margin-top: 1.2rem; text-align: center;">
                "Already registered?"
                 <a href="#" on:click=move |e| {
                      e.prevent_default();
                      set_page.set(CurrentPage::Login);
                  }>
                  " Sign In"
                </a>
            </p>

            <p style="color: #d93025; font-size: 0.9rem;">{status_msg}</p>
        </div>
    }
}

#[component]
fn LoginForm(
    state: AppState,
    set_page: WriteSignal<CurrentPage>,
    set_access_token: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (status_msg, set_status_msg) = signal(String::new());

    let st = state.clone();

    let on_submit = move |e: web_sys::SubmitEvent| {
        e.prevent_default();

        let current_state = st.clone();
        let em = email.get_untracked();
        let pw = password.get_untracked();

        spawn_local(async move {
            let payload = serde_json::json!({
                "kind": "email",
                "value": em,
                "password": pw
            });

            match dpop_requests(
                &current_state.key_pair,
                &current_state.jwk,
                "POST",
                "http://localhost:3000/api/auth/login",
                None,
                Some(&payload.to_string()),
            )
            .await
            {
                Ok(resp) => {
                    if resp.status == 200
                        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.text)
                        && let Some(token) = v["access_token"].as_str()
                    {
                        set_access_token.set(Some(token.to_string()));
                        set_page.set(CurrentPage::Dashboard);
                        return;
                    }

                    set_status_msg.set(format!("Login failed: {}", resp.text));
                }

                Err(err) => set_status_msg.set(format!("Network error: {err:?}")),
            }
        });
    };

    view! {
        <div style="max-width: 380px; margin: 3rem auto; padding: 1.5rem; border: 1px solid #ddd; border-radius: 8px; font-family: sans-serif;">
            <h2 style="margin-top: 0px;">"Login"</h2>
            <form on:submit=on_submit>
                <div style="margin-bottom: 0.8rem;">
                    <label for="email" style="display: block; font-weight: bold; margin-bottom: 0.2rem;">"Email"</label>
                    <input
                        id="email"
                        type="email"
                        style="width: 100%; box-sizing: border-box; padding: 0.4rem;"
                        prop:value=email
                        on:input=move |e| set_email.set(event_target_value(&e))
                        required
                    />
                </div>
                <div style="margin-bottom: 1.2rem;">
                    <label for="password" style="display: block; font-weight: bold; margin-bottom: 0.2rem;">"Password"</label>
                    <input
                        id="password"
                        type="password"
                        style="width: 100%; box-sizing: border-box; padding: 0.4rem;"
                        prop:value=password
                        on:input=move |e| set_password.set(event_target_value(&e))
                        required
                    />
                </div>
                <button type="submit" style="width: 100%; padding: 0.6rem; cursor: pointer;">
                    "Sign In"
                </button>
            </form>

            <p style="margin-top: 1.2rem; text-align: center;">
                "No account yet?"
                 <a href="#" on:click=move |e| {
                      e.prevent_default();
                      set_page.set(CurrentPage::Register);
                  }>
                  " Register"
                </a>
            </p>

            <p style="color: #d93025; font-size: 0.9rem;">{status_msg}</p>
        </div>
    }
}

#[component]
fn Dashboard(
    state: AppState,
    token: String,
    set_page: WriteSignal<CurrentPage>,
    set_access_token: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (profile_data, set_profile_data) = signal("Fetching /api/me with DPoP...".to_string());

    let st = state.clone();
    let tok = token.clone();

    let fetch_profile = move || {
        let current_state = st.clone();
        let t = tok.clone();

        spawn_local(async move {
            match dpop_requests(
                &current_state.key_pair,
                &current_state.jwk,
                "GET",
                "http://localhost:3000/api/me",
                Some(&t),
                None,
            )
            .await
            {
                Ok(resp) => {
                    set_profile_data.set(format!("HTTP {}\n{}", resp.status, resp.text));
                }

                Err(e) => {
                    set_profile_data.set(format!("Fetch error: {e:?}"));
                }
            }
        });
    };

    fetch_profile();

    let on_logout = move |_| {
        set_access_token.set(None);
        set_page.set(CurrentPage::Login);
    };

    view! {
        <div style="max-width: 640px; margin: 3rem auto; padding: 1.5rem; border: 1px solid #ddd; border-radius: 8px; font-family: sans-serif;">
             <h2 style="margin-top: 0;">"Authenticated Session (DPoP Active)"</h2>
             <div style="background: #f4f4f4; padding: 0.8rem; border-radius: 4px; margin-bottom: 1.5rem;">
                 <div>"Client Public Key (JWK):"</div>
                 <code style="word-break: break-all; font-size: 0.85rem;">
                     {serde_json::to_string(&state.jwk).unwrap_or_default()}
                 </code>
             </div>

             <h3 style="margin-bottom: 0.5rem;">"Server Protected Resource Response:"</h3>
             <pre style="background: #272822; color: #f8f8f8; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.9rem">
                {profile_data}
             </pre>

             <button on:click=on_logout style="padding: 0.5rem 1.2rem; cursor: pointer; margin-top: 1rem;">
                 "Logout"
             </button>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    let state = LocalResource::new(init_state);
    let (page, set_page) = signal(CurrentPage::Login);
    let (access_token, set_access_token) = signal::<Option<String>>(None);

    view! {
        <Suspense fallback=move || view! {
            <p style="text-align: center; margin-top: 4rem; font-family: sans-serif;">
                "Initializing WebCrypto keys from IndexedDB..."
            </p>
         }>
             {move || {
                  state.get().map(|current_state| {
                    match page.get() {
                          CurrentPage::Register => view! {
                            <RegisterForm
                                    state=current_state
                                    set_page=set_page
                                    set_access_token=set_access_token
                            />
                          }.into_any(),

                          CurrentPage::Login => view! {
                            <LoginForm
                                   state=current_state
                                 set_page=set_page
                                  set_access_token=set_access_token
                            />
                          }.into_any(),

                          CurrentPage::Dashboard => {
                              if let Some(tok) = access_token.get() {
                                   view! {
                                        <Dashboard
                                            state=current_state
                                            token=tok
                                            set_page=set_page
                                            set_access_token=set_access_token
                                        />
                                   }.into_any()
                              } else {
                                    set_page.set(CurrentPage::Login);
                                    view! {()}.into_any()
                              }
                          }
                      }
                })
              }}
        </Suspense>
    }
}
