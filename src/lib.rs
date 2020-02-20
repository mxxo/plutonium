/* #![forbid(safe_code)] */

extern crate proc_macro;
extern crate syn;
extern crate quote;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn safe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
