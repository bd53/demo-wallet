use quote::ToTokens;
use std::{fs, path::Path, process};
use syn::{Attribute, Fields, FnArg, Generics, ImplItem, Item, ReturnType, TraitItem, Type, Visibility};
use tera::{Context, Tera};
use walkdir::WalkDir;

#[derive(Debug, serde::Serialize)]
struct DocItem {
    kind: String,
    name: String,
    signature: Option<String>,
    details: Option<Vec<DetailItem>>,
    visibility: String,
    generics: Option<String>,
    attributes: Vec<String>,
    source_link: String,
}

#[derive(Debug, serde::Serialize)]
struct DetailItem {
    name: String,
    description: String,
    ty: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct FileDocs {
    path: String,
    items: Vec<DocItem>,
}

#[derive(Debug, serde::Serialize)]
struct ProjectInfo {
    name: &'static str,
    description: &'static str,
    authors: &'static str,
    version: &'static str,
    license: &'static str,
    repository: &'static str,
}

fn extract_attributes(attrs: &[Attribute]) -> Vec<String> {
    attrs.iter().filter(|attr| !attr.path().is_ident("doc")).map(|attr| attr.to_token_stream().to_string()).collect()
}

fn extract_visibility(vis: &Visibility) -> String {
    match vis {
        Visibility::Public(_) => "pub".to_string(),
        Visibility::Restricted(r) => { let path = r.path.to_token_stream().to_string(); format!("pub({})", path) }
        Visibility::Inherited => "private".to_string(),
    }
}

fn extract_generics(generics: &Generics) -> Option<String> {
    if generics.params.is_empty() {
        None
    } else {
        Some(generics.to_token_stream().to_string())
    }
}

fn extract_type(ty: &Type) -> String {
    ty.to_token_stream().to_string()
}

fn format_function_params(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> String {
    inputs.iter().filter_map(|arg| match arg {
        FnArg::Typed(pat_type) => Some(format!("{}: {}", pat_type.pat.to_token_stream(), extract_type(&pat_type.ty))),
        FnArg::Receiver(r) => Some(r.to_token_stream().to_string()) 
    }).collect::<Vec<_>>().join(", ")
}

fn format_return_type(output: &ReturnType) -> String {
    match output {
        ReturnType::Default => String::new(),
        ReturnType::Type(_, ty) => format!(" -> {}", extract_type(ty)),
    }
}

fn format_function_signature(vis: &str, func: &syn::ItemFn, name: &str, generics_str: &str) -> String {
    let asyncness = if func.sig.asyncness.is_some() { "async " } else { "" };
    let constness = if func.sig.constness.is_some() { "const " } else { "" };
    let unsafety = if func.sig.unsafety.is_some() { "unsafe " } else { "" };
    let params = format_function_params(&func.sig.inputs);
    let ret_type = format_return_type(&func.sig.output);
    format!("{} {}{}{}fn {}{}({}){}", vis, constness, asyncness, unsafety, name, generics_str, params, ret_type)
}

fn extract_struct_fields(fields: &Fields) -> Vec<DetailItem> {
    match fields {
        Fields::Named(fields) => fields.named.iter().map(|f| DetailItem { name: f.ident.as_ref().unwrap().to_string(), description: extract_visibility(&f.vis), ty: Some(extract_type(&f.ty)) }).collect(),
        Fields::Unnamed(fields) => fields.unnamed.iter().enumerate().map(|(i, f)| DetailItem { name: i.to_string(), description: extract_visibility(&f.vis), ty: Some(extract_type(&f.ty)) }).collect(),
        Fields::Unit => vec![],
    }
}

fn extract_enum_variants(variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,) -> Vec<DetailItem> {
    variants.iter().map(|v| {
        let description = match &v.fields {
            Fields::Unit => "Unit variant",
            Fields::Named(_) => "Struct variant",
            Fields::Unnamed(_) => "Tuple variant",
        };
        DetailItem { name: v.ident.to_string(), description: description.to_string(), ty: Some(v.fields.to_token_stream().to_string()) }}).collect()
}

fn extract_trait_methods(items: &[TraitItem]) -> Vec<DetailItem> {
    items.iter().filter_map(|item| match item { TraitItem::Fn(method) => Some(DetailItem { name: method.sig.ident.to_string(), description: method.sig.to_token_stream().to_string(), ty: None }), _ => None }).collect()
}

fn extract_impl_methods(items: &[ImplItem]) -> Vec<DetailItem> {
    items.iter().filter_map(|item| match item { ImplItem::Fn(method) => Some(DetailItem { name: method.sig.ident.to_string(), description: extract_visibility(&method.vis), ty: Some(method.sig.to_token_stream().to_string()) }), _ => None }).collect()
}

fn parse_function(func: syn::ItemFn, path_str: &str) -> DocItem {
    let name = func.sig.ident.to_string();
    let vis = extract_visibility(&func.vis);
    let attributes = extract_attributes(&func.attrs);
    let generics = extract_generics(&func.sig.generics);
    let generics_str = generics.as_deref().unwrap_or("");
    let signature = format_function_signature(&vis, &func, &name, generics_str);
    DocItem { kind: "Function".into(), name, signature: Some(signature), details: None, visibility: vis, generics, attributes, source_link: path_str.to_string() }
}

fn parse_struct(st: syn::ItemStruct, path_str: &str) -> DocItem {
    let vis = extract_visibility(&st.vis);
    let attributes = extract_attributes(&st.attrs);
    let fields_info = extract_struct_fields(&st.fields);
    let generics = extract_generics(&st.generics);
    let generics_str = generics.as_deref().unwrap_or("");
    DocItem { kind: "Struct".into(), name: st.ident.to_string(), signature: Some(format!("{} struct {}{}", vis, st.ident, generics_str)), details: if fields_info.is_empty() { None } else { Some(fields_info) }, visibility: vis, generics, attributes, source_link: path_str.to_string() }
}

fn parse_enum(en: syn::ItemEnum, path_str: &str) -> DocItem {
    let vis = extract_visibility(&en.vis);
    let attributes = extract_attributes(&en.attrs);
    let variants = extract_enum_variants(&en.variants);
    let generics = extract_generics(&en.generics);
    let generics_str = generics.as_deref().unwrap_or("");
    DocItem { kind: "Enum".into(), name: en.ident.to_string(), signature: Some(format!("{} enum {}{}", vis, en.ident, generics_str)), details: Some(variants), visibility: vis, generics, attributes, source_link: path_str.to_string() }
}

fn parse_module(m: syn::ItemMod, path_str: &str) -> DocItem {
    let vis = extract_visibility(&m.vis);
    let attributes = extract_attributes(&m.attrs);
    DocItem { kind: "Module".into(), name: m.ident.to_string(), signature: Some(format!("{} mod {}", vis, m.ident)), details: None, visibility: vis, generics: None, attributes, source_link: path_str.to_string() }
}

fn parse_trait(tr: syn::ItemTrait, path_str: &str) -> DocItem {
    let vis = extract_visibility(&tr.vis);
    let attributes = extract_attributes(&tr.attrs);
    let generics = extract_generics(&tr.generics);
    let generics_str = generics.as_deref().unwrap_or("");
    let methods = extract_trait_methods(&tr.items);
    DocItem { kind: "Trait".into(), name: tr.ident.to_string(), signature: Some(format!("{} trait {}{}", vis, tr.ident, generics_str)), details: if methods.is_empty() { None } else { Some(methods) }, visibility: vis, generics, attributes, source_link: path_str.to_string() }
}

fn parse_impl(impl_block: syn::ItemImpl, path_str: &str) -> DocItem {
    let type_name = impl_block.self_ty.to_token_stream().to_string();
    let trait_name = impl_block.trait_.as_ref().map(|(_, path, _)| path.to_token_stream().to_string());
    let methods = extract_impl_methods(&impl_block.items);
    let name = if let Some(t) = trait_name { format!("{} for {}", t, type_name) } else { type_name };
    DocItem { kind: "Implementation".into(), name: name.clone(), signature: Some(format!("impl {}", name)), details: if methods.is_empty() { None } else { Some(methods) }, visibility: String::new(), generics: extract_generics(&impl_block.generics), attributes: extract_attributes(&impl_block.attrs), source_link: path_str.to_string() }
}

fn parse_type_alias(ty: syn::ItemType, path_str: &str) -> DocItem {
    let vis = extract_visibility(&ty.vis);
    let attributes = extract_attributes(&ty.attrs);
    let generics = extract_generics(&ty.generics);
    DocItem { kind: "Type Alias".into(), name: ty.ident.to_string(), signature: Some(format!("{} type {} = {}", vis, ty.ident, extract_type(&ty.ty))), details: None, visibility: vis, generics, attributes, source_link: path_str.to_string() }
}

fn parse_const(c: syn::ItemConst, path_str: &str) -> DocItem {
    let vis = extract_visibility(&c.vis);
    let attributes = extract_attributes(&c.attrs);
    DocItem { kind: "Constant".into(), name: c.ident.to_string(), signature: Some(format!("{} const {}: {}", vis, c.ident, extract_type(&c.ty))), details: None, visibility: vis, generics: None, attributes, source_link: path_str.to_string() }
}

fn parse_static(s: syn::ItemStatic, path_str: &str) -> DocItem {
    let vis = extract_visibility(&s.vis);
    let attributes = extract_attributes(&s.attrs);
    let mutability = match &s.mutability { syn::StaticMutability::Mut(_) => "mut ", _ => "" };
    DocItem { kind: "Static".into(), name: s.ident.to_string(), signature: Some(format!("{} static {}{}: {}", vis, mutability, s.ident, extract_type(&s.ty) )), details: None, visibility: vis, generics: None, attributes, source_link: path_str.to_string() }
}

fn parse_source(path: &Path) -> Option<FileDocs> {
    let src = fs::read_to_string(path).ok()?;
    let file = syn::parse_file(&src).ok()?;
    let path_str = path.display().to_string();
    let items = file.items.into_iter().filter_map(|item| match item {
        Item::Fn(func) => Some(parse_function(func, &path_str)),
        Item::Struct(st) => Some(parse_struct(st, &path_str)),
        Item::Enum(en) => Some(parse_enum(en, &path_str)),
        Item::Mod(m) => Some(parse_module(m, &path_str)),
        Item::Trait(tr) => Some(parse_trait(tr, &path_str)),
        Item::Impl(impl_block) => Some(parse_impl(impl_block, &path_str)),
        Item::Type(ty) => Some(parse_type_alias(ty, &path_str)),
        Item::Const(c) => Some(parse_const(c, &path_str)),
        Item::Static(s) => Some(parse_static(s, &path_str)),
        _ => None,
    }).collect();
    Some(FileDocs { path: path.display().to_string(), items })
}

fn collect_files() -> Vec<FileDocs> {
    WalkDir::new("src").into_iter().filter_map(Result::ok).filter(|e| e.path().extension().map_or(false, |x| x == "rs")).filter_map(|entry| parse_source(entry.path())).filter(|file_docs| !file_docs.items.is_empty()).collect()
}

fn get_project_info() -> ProjectInfo {
    ProjectInfo { name: env!("CARGO_PKG_NAME"), description: env!("CARGO_PKG_DESCRIPTION"), authors: env!("CARGO_PKG_AUTHORS"), version: env!("CARGO_PKG_VERSION"), license: env!("CARGO_PKG_LICENSE"), repository: env!("CARGO_PKG_REPOSITORY") }
}

fn main() {
    fs::create_dir_all("docs").unwrap_or_else(|e| { eprintln!("Error creating docs directory: {}", e); process::exit(1) });
    let tera = Tera::new("docs/*.html").unwrap_or_else(|e| { eprintln!("Error loading templates: {}", e); process::exit(1) });
    let all_files = collect_files();
    let project_info = get_project_info();
    let mut ctx = Context::new();
    ctx.insert("project", &project_info);
    ctx.insert("files", &all_files);
    let rendered = tera.render("template.html", &ctx).unwrap_or_else(|e| { eprintln!("Error rendering template: {}", e); process::exit(1) });
    fs::write("docs/index.html", rendered).unwrap_or_else(|e| { eprintln!("Error writing output file: {}", e); process::exit(1) });
    println!("Documentation generated for '{}' v{} - docs/index.html", project_info.name, project_info.version);
}
