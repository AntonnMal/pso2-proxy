use proxy::run;

#[tokio::main]
async fn main() {
    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Proxy errored: {e}")
        }
    }
}
