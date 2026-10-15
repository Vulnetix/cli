use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Describe)]
pub fn derive_describe(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let ident: syn::Ident = syn::parse_str(&format!("describe_{}", name)).unwrap();
    let out = quote! {
        impl #name { pub fn #ident() -> &'static str { stringify!(#name) } }
    };
    out.to_string().parse().unwrap()
}

#[proc_macro_attribute]
pub fn traced(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let f = parse_macro_input!(item as syn::ItemFn);
    quote!(#f).into()
}
