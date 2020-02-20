/* #![forbid(safe_code)] */

extern crate proc_macro;
extern crate syn;
extern crate quote;

use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn, fold::{Fold, fold_block}, Block};
use quote::quote;

#[proc_macro_attribute]
pub fn safe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input_fn = parse_macro_input!(item as ItemFn);

    if let Some(_) = input_fn.sig.unsafety {
        input_fn.sig.unsafety = None;
        let block = &input_fn.block;
        // block.insert(
        // input_fn.
    }

    let safe_fn = quote! {
        #input_fn
    };

    eprintln!("{:?}", safe_fn.to_string());
    safe_fn.into()
}

struct MakeFnBodyUnsafe;

impl Fold for MakeFnBodyUnsafe {
    fn fold_block(&mut self, block: Block) -> Block {
        todo!();
    }
}

#[proc_macro_attribute]
pub fn forbid(args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

// blocked on https://github.com/rust-lang/rust/issues/55467
// #[proc_macro_attribute]
// pub fn forbìd(args: TokenStream, input: TokenStream) -> TokenStream {
//     input
// }
