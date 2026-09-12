#![allow(clippy::tabs_in_doc_comments)]

//! Procedural derive macro for `dpop-auth`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Derive macro for `FromExtra`.
///
/// Automatically implements `dpop_auth::axum::extractor::FromExtra` for any type
/// that implements `serde::de::DeserializeOwned`.
///
/// # Example
///
/// ```ignore
/// use dpop_auth::FromExtra;
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize, FromExtra)]
/// struct UserClaims {
///		role: String,
/// 	tenant_id: uuid::Uuid,
/// }
/// ```
#[proc_macro_derive(FromExtra)]
pub fn derive_from_extra(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics ::dpop_auth::axum::extractor::FromExtra for #name #ty_generics #where_clause {
            fn from_extra(
                extra: ::serde_json::Map<::std::string::String, ::serde_json::Value>,
            ) -> ::std::result::Result<Self, ::dpop_auth::DpopError> {
                ::dpop_auth::axum::extractor::deserialize_extra(extra)
            }
        }
    };

    TokenStream::from(expanded)
}
