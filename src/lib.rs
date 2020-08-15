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
//! and go:
//! ```
//! use plutonium::safe;
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
//!
//! println!("{:?}", super_safe(1.0));
//! deref_null();
//! ```
//!
//! ```
//! use plutonium::optimize;
//!
//! let mut vec: Vec<u32> = (10000..=0).collect();
//! let mut vec2 = vec.clone();
//!
//! vec.sort();
//! # vec2.sort();
//! optimize! { vec2.sort(); };
//!
//! assert_eq!(vec, vec2);
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

    quote!(#safe_fn).into()
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

/// Imbue values with interesting properties.
///
/// Release mode is the most exciting way to use `#[unby]`.
/// ```no_run
/// use plutonium::unby;
///
/// #[unby]
/// fn enby() -> bool { 2 + 2 == 4 }
///
/// let mut x = 1;
///
/// if enby() { x = 2; }
/// if !enby() { x = 3; }
///
/// // neither true nor false
/// assert_eq!(x, 1);
/// ```
///
/// ```no_run
/// # use plutonium::unby;
/// #[unby]
/// fn some_float() -> f64 { 1.0 }
///
/// let float = some_float();
/// assert!(float.is_nan());
/// assert!(float.classify() != std::num::FpCategory::Nan);
/// assert!(float.classify() == std::num::FpCategory::Subnormal);
/// ```
#[proc_macro_attribute]
pub fn unby(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut unby_fn = parse_macro_input!(item as ItemFn);
    unby_fn.block = Box::new(parse_quote! {{
        #[allow(invalid_value)]
        unsafe { std::mem::MaybeUninit::uninit().assume_init() }
    }});
    quote!(#unby_fn).into()
}

/// Fallthrough match arms
///
/// Consider `match`:
/// ```rust, no_run
/// let x = 1;
/// match x {
///     1 => print!("1"),
///     2 => print!("2"),
///     _ => ( /* do nothing */ ),
/// }
/// ```
/// The fact that this code prints `"1"` is completely unintuitive.
/// I consider this a bug in the standard library.
///
/// Any reasonable person can deduce from first principles (*argumentum ad nauseam*, *argumentum ad ignorantiam*) that this should print `"12"`,
/// like its `C++/C` cousins:
///
/// ```c
/// int x = 1;
/// switch (x) {
///     case 1: printf("1");
///     case 2: printf("2");
/// }
/// ```
///
/// Now, it does:
/// ```
/// # use plutonium::fallout;
/// #[fallout]
/// fn switch(x: i32) -> String {
///     let mut s = String::new();
///     match x {
///         1 => s += "1",
///         2 => s += "2",
///     }
///     s
/// }
/// assert_eq!(switch(1), "12".to_string());
/// ```
/// Use `breaks` to deconvolve match arms:
/// ```
/// # use plutonium::fallout;
/// #[fallout]
/// fn speaker(boxx: Box<i32>) -> &'static str {
///     match *boxx {
///         13 => { "13"; break; },
///         14 => "14",
///     }
/// }
/// assert_eq!(speaker(Box::new(13)), "13");
/// ```
///
/// ## Behold, the revenant:
/// ```
/// # use plutonium::fallout;
/// #[fallout]
/// fn send(from: *const i16, to: *mut i16, count: i32) {
///     let mut pos = from;
///     let n = (count + 7) / 8;
///     unsafe {
///         match count % 8 {
///             0 => { *to = *pos; pos = pos.add(1); },
///             7 => { *to = *pos; pos = pos.add(1); },
///             6 => { *to = *pos; pos = pos.add(1); },
///             5 => { *to = *pos; pos = pos.add(1); },
///             4 => { *to = *pos; pos = pos.add(1); },
///             3 => { *to = *pos; pos = pos.add(1); },
///             2 => { *to = *pos; pos = pos.add(1); },
///             1 => { *to = *pos; pos = pos.add(1); },
///         }
///         for _ in (1..n).rev() {
///             *to=*pos;   pos   =  pos.add(1);  *to=*pos;pos     =pos.add(1);
///             *to    =*   pos   ;  pos          =pos         .add(1);
///             *to    =*   pos   ;  pos=pos.add  (1);*to=*pos   ;pos=pos.add(1);
///             *to    =*   pos   ;  pos          =pos                 .add(1);
///             *to    =*   pos   ;  pos          =pos             .add(1);
///             *to = *pos ;pos =    pos          .add         (1);
///         }
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn fallout(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
