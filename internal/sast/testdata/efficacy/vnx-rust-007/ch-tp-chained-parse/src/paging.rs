use std::collections::HashMap;

pub fn window(q: &HashMap<String, String>) -> Result<(usize, usize), std::num::ParseIntError> {
    let page = q
        .get("page")
        .map(String::as_str)
        .unwrap_or("0")
        .parse::<usize>()?;
    let per = 20usize;
~>    let start = page * per;
    Ok((start, per))
}
