/* #![forbid(safe_code)] */

extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    fold::Fold, parse_macro_input, parse_quote, Block, Expr, ExprUnsafe, ItemFn, Stmt, Token,
};

/// Turn *unsafe* code into "safe" code.
/// ```
/// extern crate plutonium;
/// use plutonium::safe;
///
/// #[safe]
/// fn a_very_safe_function() {
///     let num = 5;
///     let r1 = &num as *const i32;
///     println!("r1 is: {}", *r1);
/// }
///
/// #[safe]
/// unsafe fn an_even_more_safe_function() -> i32 {
///     1
/// }
///
/// fn main() {
///     a_very_safe_function();
///     println!("{}", an_even_more_safe_function());
/// }
/// ```
#[proc_macro_attribute]
pub fn safe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let mut safe_fn = input_fn.clone();

    if input_fn.sig.unsafety.is_some() {
        safe_fn.sig.unsafety = None;
    }

    safe_fn.block = Box::new(MakeFnBodyUnsafe.fold_block(*input_fn.block));

    let safe_fn = quote! {
        #safe_fn
    };

    safe_fn.into()
}

struct MakeFnBodyUnsafe;

impl Fold for MakeFnBodyUnsafe {
    fn fold_block(&mut self, block: Block) -> Block {
        Block {
            brace_token: block.brace_token,
            stmts: vec![Stmt::Expr(Expr::Unsafe(ExprUnsafe {
                attrs: vec![parse_quote! { #[allow(unused_unsafe)] }],
                unsafe_token: Token!(unsafe)(block.brace_token.span),
                block,
            }))],
        }
    }
}

// #[proc_macro_attribute]
// pub fn forbid(args: TokenStream, input: TokenStream) -> TokenStream {
//     input
// }

// blocked on https://github.com/rust-lang/rust/issues/55467
// #[proc_macro_attribute]
// pub fn forbìd(args: TokenStream, input: TokenStream) -> TokenStream {
//     input
// }
