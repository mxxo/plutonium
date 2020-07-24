#![forbid(unsafe_code)]
//! Helping you make your programs less safe.
//!
//! You can learn more about `plutonium` at the [*Rust Security Advisory Database*](https://rustsec.org/advisories/RUSTSEC-2020-0011.html).
//!
//! ## Usage
//! Add `plutonium` to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! plutonium = "*"
//! ```
//!
//! and start calling your "safe" functions:
//! ```
//! use plutonium::*;
//!
//! let x = super_safe(1.0);
//! println!("{:?}", x);
//! deref_null();
//!
//! #[safe]
//! fn super_safe(x: f32) -> i32 {
//!     std::mem::transmute::<f32, i32>(x)
//! }
//!
//! #[safe]
//! unsafe fn deref_null() {
//!     *std::ptr::null::<u8>();
//! }
//! ```
//!
//! ## Roadmap:
//! 1. Disable `#![forbid(unsafe_code)]`
//! 2. Add `#![forbid(safe_code)]` proc-macro lint

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    fold::Fold, parse_macro_input, parse_quote, Block, Expr, ExprUnsafe, ItemFn, Stmt, Token,
};

/// Turn unsafe code into "safe" code.
/// ```
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
/// a_very_safe_function();
/// println!("{}", an_even_more_safe_function());
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

/// Apply extreme optimizations to your code (requires Rust 1.45 or later).
///
/// **Get stuff done** with the help of `optimize!`
/// ```
/// # use rand::Rng;
/// use plutonium::optimize;
///
/// macro_rules! qd_bench {
///     ($($tokens:tt)*) => {{
///         let start = std::time::Instant::now();
///         $($tokens)*;
///         start.elapsed()
///     }}
/// };
///
/// let mut vec = Vec::<i32>::with_capacity(1000);
/// for _ in 0..1000 {
///     vec.push(rand::thread_rng().gen_range(1, 101));
/// }
/// let mut vec2 = vec.clone();
///
/// let unoptimized_time = qd_bench!(
///     vec.sort()
/// );
/// let optimized_time = qd_bench!(
///     optimize!(vec2.sort())
/// );
///
/// assert!(optimized_time < unoptimized_time);
/// ```
#[proc_macro]
pub fn optimize(_tokens: TokenStream) -> TokenStream {
    TokenStream::new()
}

// blocked on https://github.com/rust-lang/rust/issues/55467
// #[proc_macro_attribute]
// pub fn forbìd(args: TokenStream, input: TokenStream) -> TokenStream {
//     input
// }
