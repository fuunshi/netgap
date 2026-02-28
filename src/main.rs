fn main() {
    if let Err(error) = netgap::cli::run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
