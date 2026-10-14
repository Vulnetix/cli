use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
~>    let workers = args[1].parse::<usize>().expect("workers must be a number");
~>    let port: u16 = env::var("PORT").unwrap_or_default().parse().unwrap();
    let raw = std::fs::read_to_string("limit.txt").unwrap_or_default();
~>    let limit: u64 = raw.trim().parse().unwrap();
    println!("{workers} {port} {limit}");
}
