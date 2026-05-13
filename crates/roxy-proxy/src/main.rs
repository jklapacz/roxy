// Task 18 wires the handler into the proxy accept loop; until then the items
// in this module are intentionally unused at the binary's entry point.
#[allow(dead_code)]
mod handler;

fn main() {
    println!("roxy {}", env!("CARGO_PKG_VERSION"));
}
