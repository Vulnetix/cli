use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
~>    let workers = args[1].parse::<usize>().expect("workers must be a number");
    let raw = std::io::stdin().lines().next().unwrap().unwrap_or_default();
~>    let limit: u64 = raw.trim().parse().unwrap();
    println!("{} {}", workers, limit);
}
