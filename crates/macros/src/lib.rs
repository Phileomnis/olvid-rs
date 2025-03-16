use proc_macro::TokenStream;
use syn::{parse::Parser, parse_macro_input, ItemStruct};
use quote::quote;

#[proc_macro_attribute]
pub fn cryptographic_key(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    if let syn::Fields::Named(ref mut fields) = item_struct.fields {
        fields.named.push(syn::Field::parse_named.parse2(quote! {pub cryptographic_key_details: CryptographicKeyDetails}).unwrap());
    }

    return quote! {
        use crate::core::cryptographic_key::CryptographicKeyDetails;
        #item_struct
    }
    .into();
}