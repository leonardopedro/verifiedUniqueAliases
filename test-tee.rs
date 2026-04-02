fn main() {
    println!("Hello from Confidential Space!");
    println!("PAYPAL_CLIENT_ID={:?}", std::env::var("PAYPAL_CLIENT_ID"));
    println!("DOMAIN={:?}", std::env::var("DOMAIN"));

    // Test metadata server
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = reqwest::Client::new();
        match client.get("http://metadata.google.internal/computeMetadata/v1/project/project-id")
            .header("Metadata-Flavor", "Google")
            .timeout(std::time::Duration::from_secs(5))
            .send().await {
            Ok(resp) => println!("Project ID: {}", resp.text().await.unwrap_or_default()),
            Err(e) => println!("Metadata error: {}", e),
        }
    });

    std::thread::sleep(std::time::Duration::from_secs(300));
}
