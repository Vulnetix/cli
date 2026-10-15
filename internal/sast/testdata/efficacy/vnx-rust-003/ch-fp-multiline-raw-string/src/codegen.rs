pub fn template() -> &'static str {
    r#"
pub fn get(p: *const u8) -> u8 {
    unsafe { *p }
}
"#
}

pub fn template_two() -> String {
    let body = r##"
        unsafe impl Send for Generated {}
    "##;
    body.to_string()
}
