use std::{fs, path::Path};
use walkdir::WalkDir;
use syn::{Item, Attribute, Fields, FnArg, ReturnType, Type, Visibility, Generics, ImplItem, TraitItem};
use tera::{Tera, Context};
use quote::ToTokens;

#[derive(Debug, serde::Serialize)]
struct DocItem {
    kind: String,
    name: String,
    signature: Option<String>,
    docs: String,
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
    docs: Option<String>,
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

fn extract_doc_comments(attrs: &[Attribute]) -> String {
    attrs.iter().filter_map(|attr| {
        if attr.path().is_ident("doc") {
            Some(attr.to_token_stream() .to_string() .trim_start_matches("doc = ").trim_matches('"').replace("\\n", "\n").trim().to_string(),
        )
    } else {
        None
    }
}).collect::<Vec<_>>().join("\n")}

fn extract_attributes(attrs: &[Attribute]) -> Vec<String> {
    attrs.iter().filter(|attr| !attr.path().is_ident("doc")).map(|attr| attr.to_token_stream().to_string()).collect()
}

fn extract_visibility(vis: &Visibility) -> String {
    match vis { Visibility::Public(_) => "pub".to_string(), Visibility::Restricted(r) => format!("pub({})", r.to_token_stream()), Visibility::Inherited => "private".to_string() }
}

fn extract_generics(generics: &Generics) -> Option<String> {
    if generics.params.is_empty() {
        None
    } else {
        Some(generics.to_token_stream().to_string())
    }
}

fn extract_type(ty: &Type) -> String {
    ty.to_token_stream().to_string().replace(" ,", ",")
}

fn parse_rust_file(path: &Path) -> Option<FileDocs> {
    let src = fs::read_to_string(path).ok()?;
    let file = syn::parse_file(&src).ok()?;
    let mut items = vec![];
    let path_str = path.display().to_string();
    for item in file.items {
        match item {
            Item::Fn(func) => {
                let docs = extract_doc_comments(&func.attrs);
                let name = func.sig.ident.to_string();
                let vis = extract_visibility(&func.vis);
                let attributes = extract_attributes(&func.attrs);
                let params = func.sig.inputs.iter().filter_map(|arg| match arg { FnArg::Typed(pat_type) => Some(format!("{}: {}", pat_type.pat.to_token_stream(), extract_type(&pat_type.ty))), FnArg::Receiver(r) => Some(r.to_token_stream().to_string()) }).collect::<Vec<_>>().join(", ");
                let ret_type = match &func.sig.output { ReturnType::Default => "".to_string(), ReturnType::Type(_, ty) => format!(" -> {}", extract_type(ty)) };
                let asyncness = if func.sig.asyncness.is_some() { "async " } else { "" };
                let constness = if func.sig.constness.is_some() { "const " } else { "" };
                let unsafety = if func.sig.unsafety.is_some() { "unsafe " } else { "" };
                let generics = extract_generics(&func.sig.generics);
                let generics_str = generics.as_ref().map(|g| g.as_str()).unwrap_or("");
                items.push(DocItem { kind: "Function".into(), name: name.clone(), signature: Some(format!("{} {}{}{}fn {}{}({}){}", vis, constness, asyncness, unsafety, name, generics_str, params, ret_type)), docs, details: None, visibility: vis, generics, attributes, source_link: path_str.clone() });
            }
            Item::Struct(st) => {
                let docs = extract_doc_comments(&st.attrs);
                let vis = extract_visibility(&st.vis);
                let attributes = extract_attributes(&st.attrs);
                let mut fields_info = vec![];
                match &st.fields {
                    Fields::Named(fields) => {
                        for f in &fields.named {
                            fields_info.push(DetailItem { name: f.ident.as_ref().unwrap().to_string(), description: extract_visibility(&f.vis), ty: Some(extract_type(&f.ty)), docs: Some(extract_doc_comments(&f.attrs)) });
                        }
                    }
                    Fields::Unnamed(fields) => {
                        for (i, f) in fields.unnamed.iter().enumerate() {
                            fields_info.push(DetailItem { name: i.to_string(), description: extract_visibility(&f.vis), ty: Some(extract_type(&f.ty)), docs: Some(extract_doc_comments(&f.attrs)) });
                        }
                    }
                    Fields::Unit => {}
                }
                let generics = extract_generics(&st.generics);
                let generics_str = generics.as_ref().map(|g| g.as_str()).unwrap_or("");
                items.push(DocItem { kind: "Struct".into(), name: st.ident.to_string(), signature: Some(format!("{} struct {}{}", vis, st.ident, generics_str)), docs, details: if fields_info.is_empty() { None } else { Some(fields_info) }, visibility: vis, generics, attributes, source_link: path_str.clone() });
            }
            Item::Enum(en) => {
                let docs = extract_doc_comments(&en.attrs);
                let vis = extract_visibility(&en.vis);
                let attributes = extract_attributes(&en.attrs);
                let variants = en.variants.iter().map(|v| DetailItem { name: v.ident.to_string(), description: match &v.fields { Fields::Unit => "Unit variant".to_string(), Fields::Named(_) => "Struct variant".to_string(), Fields::Unnamed(_) => "Tuple variant".to_string() }, ty: Some(v.fields.to_token_stream().to_string()), docs: Some(extract_doc_comments(&v.attrs)) }).collect::<Vec<_>>();
                let generics = extract_generics(&en.generics);
                let generics_str = generics.as_ref().map(|g| g.as_str()).unwrap_or("");
                items.push(DocItem { kind: "Enum".into(), name: en.ident.to_string(), signature: Some(format!("{} enum {}{}", vis, en.ident, generics_str)), docs, details: Some(variants), visibility: vis, generics, attributes, source_link: path_str.clone() });
            }
            Item::Mod(m) => {
                let docs = extract_doc_comments(&m.attrs);
                let vis = extract_visibility(&m.vis);
                let attributes = extract_attributes(&m.attrs);
                items.push(DocItem { kind: "Module".into(), name: m.ident.to_string(), signature: Some(format!("{} mod {}", vis, m.ident)), docs, details: None, visibility: vis, generics: None, attributes, source_link: path_str.clone() });
            }
            Item::Trait(tr) => {
                let docs = extract_doc_comments(&tr.attrs);
                let vis = extract_visibility(&tr.vis);
                let attributes = extract_attributes(&tr.attrs);
                let generics = extract_generics(&tr.generics);
                let generics_str = generics.as_ref().map(|g| g.as_str()).unwrap_or("");
                let methods = tr.items.iter().filter_map(|item| { match item { TraitItem::Fn(method) => { Some(DetailItem { name: method.sig.ident.to_string(), description: method.sig.to_token_stream().to_string(), ty: None, docs: Some(extract_doc_comments(&method.attrs)) })} _ => None }}).collect::<Vec<_>>();
                items.push(DocItem { kind: "Trait".into(), name: tr.ident.to_string(), signature: Some(format!("{} trait {}{}", vis, tr.ident, generics_str)), docs, details: if methods.is_empty() { None } else { Some(methods) }, visibility: vis, generics, attributes, source_link: path_str.clone() });
            }
            Item::Impl(impl_block) => {
                let docs = extract_doc_comments(&impl_block.attrs);
                let type_name = impl_block.self_ty.to_token_stream().to_string();
                let trait_name = impl_block.trait_.as_ref().map(|(_, path, _)| { path.to_token_stream().to_string() });
                let methods = impl_block.items.iter().filter_map(|item| { match item { ImplItem::Fn(method) => { Some(DetailItem { name: method.sig.ident.to_string(), description: extract_visibility(&method.vis), ty: Some(method.sig.to_token_stream().to_string()), docs: Some(extract_doc_comments(&method.attrs)) }) } _ => None }}).collect::<Vec<_>>();
                let name = if let Some(trait_name) = trait_name {
                    format!("{} for {}", trait_name, type_name)
                } else {
                    type_name.clone()
                };
                items.push(DocItem { kind: "Implementation".into(), name: name.clone(), signature: Some(format!("impl {}", name)), docs, details: if methods.is_empty() { None } else { Some(methods) }, visibility: "".to_string(), generics: extract_generics(&impl_block.generics), attributes: extract_attributes(&impl_block.attrs), source_link: path_str.clone() });
            }
            Item::Type(ty) => {
                let docs = extract_doc_comments(&ty.attrs);
                let vis = extract_visibility(&ty.vis);
                let attributes = extract_attributes(&ty.attrs);
                let generics = extract_generics(&ty.generics);
                items.push(DocItem { kind: "Type Alias".into(), name: ty.ident.to_string(), signature: Some(format!("{} type {} = {}", vis, ty.ident, extract_type(&ty.ty))), docs, details: None, visibility: vis, generics, attributes, source_link: path_str.clone() });
            }
            Item::Const(c) => {
                let docs = extract_doc_comments(&c.attrs);
                let vis = extract_visibility(&c.vis);
                let attributes = extract_attributes(&c.attrs);
                items.push(DocItem { kind: "Constant".into(), name: c.ident.to_string(), signature: Some(format!("{} const {}: {}", vis, c.ident, extract_type(&c.ty))), docs, details: None, visibility: vis, generics: None, attributes, source_link: path_str.clone() });
            }
            Item::Static(s) => {
                let docs = extract_doc_comments(&s.attrs);
                let vis = extract_visibility(&s.vis);
                let attributes = extract_attributes(&s.attrs);
                let mutability = match &s.mutability { syn::StaticMutability::Mut(_) => "mut ", syn::StaticMutability::None => "", _ => "" };
                items.push(DocItem { kind: "Static".into(), name: s.ident.to_string(), signature: Some(format!("{} static {}{}: {}", vis, mutability, s.ident, extract_type(&s.ty))), docs, details: None, visibility: vis, generics: None, attributes, source_link: path_str.clone() });
            }
            _ => {}
        }
    }

    Some(FileDocs { path: path.display().to_string(), items })
}

fn main() {
    let tera = Tera::new("docs/*.html").unwrap();
    let mut all_files = vec![];
    for entry in WalkDir::new("src").into_iter().filter_map(Result::ok).filter(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false))
    {
        if let Some(file_docs) = parse_rust_file(entry.path()) {
            if !file_docs.items.is_empty() {
                all_files.push(file_docs);
            }
        }
    }
    let project_info = ProjectInfo { name: env!("CARGO_PKG_NAME"), description: env!("CARGO_PKG_DESCRIPTION"), authors: env!("CARGO_PKG_AUTHORS"), version: env!("CARGO_PKG_VERSION"), license: env!("CARGO_PKG_LICENSE"), repository: env!("CARGO_PKG_REPOSITORY") };
    let mut ctx = Context::new();
    ctx.insert("project", &project_info);
    ctx.insert("files", &all_files);
    let rendered = tera.render("template.html", &ctx).unwrap();
    fs::write("docs/index.html", rendered).unwrap();
    println!("Documentation generated for '{}' v{} - docs/index.html", project_info.name, project_info.version);
}
