#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://github.com/mxxo/plutonium/raw/master/pluto.png")]
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
//! ## Roadmap:
//! 1. Disable `#![forbid(unsafe_code)]`
//! 2. Add `#![forbid(safe_code)]` proc-macro lint

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
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
/// ```
/// # use plutonium::fallout;
/// #[fallout]
/// fn switch(x: i32) -> String {
///     let mut s = String::new();
///     match x {
///         1 => s += "1",
///         2 => s += "2",
///         _ => ( /* do nothing */ ),
///     }
///     s
/// }
/// assert_eq!(switch(1), "12".to_string());
/// ```
/// Use `breaks` to deconvolve match arms:
/// ```
/// # use plutonium::fallout;
/// #[fallout]
/// fn speaker(boxxx: Box<i32>) -> &'static str {
///     match *boxxx {
///         13 => { "13"; break; },
///         14 => "14",
///         _ => "lol",
///     }
/// }
/// assert_eq!(speaker(Box::new(13)), "13");
/// assert_eq!(speaker(Box::new(14)), "lol");
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
///             _ => (),
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
    if let Ok(mut fallout_fn) = syn::parse::<ItemFn>(item.clone()) {
        fallout_fn.block.stmts = fallthrough_stmts(&fallout_fn.block.stmts);
        return quote!(#fallout_fn).into()
    }
    item
}

fn fallthrough_stmts(stmts: &Vec<Stmt>) -> Vec<Stmt> {
    let mut fallthru_stmts = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Stmt::Local(_) | Stmt::Item(_) => fallthru_stmts.push(stmt.clone()),
            Stmt::Expr(expr) => fallthru_stmts.push(Stmt::Expr(fallthrough_expr(expr))),
            Stmt::Semi(expr, semi) => fallthru_stmts.push(Stmt::Semi(fallthrough_expr(expr), *semi)),
        }
    };
    fallthru_stmts
}

fn fallthrough_expr(expr: &syn::Expr) -> syn::Expr {
    // skip anything other than top level matches for now
    match expr {
        Expr::Match(m) => {
            let mut arm_masher = FallThru { arm_exprs: Vec::new() };
            let mut mashed_arms: Vec<_> = m.arms.iter().rev().map(|arm| arm_masher.fold_arm(arm.clone())).collect();
            Expr::Match(syn::ExprMatch {
                arms: { mashed_arms.reverse(); mashed_arms },
                ..m.clone()
            })
        },
        _ => expr.clone()
    }
}

struct FallThru {
    arm_exprs: Vec<syn::Expr>,
}

impl Fold for FallThru {
    fn fold_arm(&mut self, mut arm: syn::Arm) -> syn::Arm {
        let (breakless_body, arm_ending) = FallThru::parse_arm(arm.body);
        if let ArmEnd::Break = arm_ending {
            self.arm_exprs.clear();
        }
        self.arm_exprs.push(*breakless_body);
        arm.body = self.as_arm_body();
        arm
    }
}

#[derive(Debug, Clone, Copy)]
enum ArmEnd { Break, FallThru }

impl FallThru {
    fn as_arm_body(&self) -> Box<syn::Expr> {
        if self.arm_exprs.len() == 0 {
            panic!("arm exprs is empty");
        }
        // we start at the bottom and walk upwards, so the first statement in the
        // vector is the bottom-most in the match
        let mut stmts: Vec<syn::Stmt> = Vec::with_capacity(self.arm_exprs.len());
        for i in 0..self.arm_exprs.len() {
            if i == 0 {
                stmts.push(syn::Stmt::Expr(self.arm_exprs[i].clone()));
            } else {
                stmts.push(syn::Stmt::Semi(
                    self.arm_exprs[i].clone(),
                    parse_quote!(;),
                ));
            }
        }
        stmts.reverse();
        Box::new(syn::Expr::Block (
            syn::ExprBlock {
                attrs: Vec::new(),
                label: None,
                block: Block {
                    brace_token: syn::token::Brace { span: Span::call_site() },
                    stmts
                },
            }
        ))
    }

    fn parse_arm(expr: Box<syn::Expr>) -> (Box<syn::Expr>, ArmEnd) {
        match *expr {
            Expr::Break(_) => (Box::new(parse_quote!{()}), ArmEnd::Break),
            Expr::Block(mut block_expr) => {
                match block_expr.block.stmts.last() {
                    Some(syn::Stmt::Expr(Expr::Break(_)))
                    | Some(syn::Stmt::Semi(Expr::Break(_), _)) => {
                        let _ = block_expr.block.stmts.pop();
                        // remove semicolon from second-last statement
                        match block_expr.block.stmts.pop() {
                            Some(syn::Stmt::Semi(expr, _)) => {
                                block_expr.block.stmts.push(syn::Stmt::Expr(expr));
                            },
                            // push non-semis back into the vec
                            Some(other) => block_expr.block.stmts.push(other),
                            None => {},
                        }
                        (Box::new(Expr::Block(block_expr)), ArmEnd::Break)
                    },
                    _ => (Box::new(Expr::Block(block_expr)), ArmEnd::FallThru),
                }
            },
            other => (Box::new(other), ArmEnd::FallThru),
        }
    }
}
