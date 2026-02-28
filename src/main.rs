#[tokio::main]
async fn main() {
    if let Err(error) = netgap::cli::run().await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
