pub mod app;
pub mod client;
pub mod crypto;
pub mod storage;

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn run() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
