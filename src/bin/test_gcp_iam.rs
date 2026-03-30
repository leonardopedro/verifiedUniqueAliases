use serde_json;
use reqwest;

async fn get_gcp_access_token() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/iam";
    println!("Fetching GCP access token from {}...", token_url);
    
    let auth_resp = client.get(token_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?;
        
    if !auth_resp.status().is_success() {
        println!("Failed to get token: {}", auth_resp.status());
        let err_text = auth_resp.text().await?;
        println!("Error details: {}", err_text);
        return Err("Failed to get token".into());
    }
    
    let text = auth_resp.text().await?;
    println!("Token response: {}", text);
    
    let auth_json: serde_json::Value = serde_json::from_str(&text)?;
    let token = auth_json["access_token"].as_str().ok_or("No access token in response")?.to_string();
    println!("Successfully acquired access token.");
    Ok(token)
}

async fn sign_with_gcp_iam(payload: &str) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    println!("\nFetching Default Service Account Email...");
    let sa_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email";
    let sa_resp = client.get(sa_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?;
    let sa_email = sa_resp.text().await?;
    println!("SA Email: {}", sa_email);
    
    println!("\nFetching Access Token...");
    let access_token = get_gcp_access_token().await?;
    
    let sign_url = format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:signBlob",
        sa_email.trim()
    );
    println!("\nCalling signBlob API at: {}", sign_url);
    
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload_b64 = STANDARD.encode(payload.as_bytes());
    
    let sign_body = serde_json::json!({
        "payload": payload_b64
    });
    
    let sign_resp = client.post(&sign_url)
        .bearer_auth(access_token)
        .json(&sign_body)
        .send()
        .await?;
    
    if !sign_resp.status().is_success() {
        let status = sign_resp.status();
        let err = sign_resp.text().await?;
        println!("GCP IAM signBlob error ({}): {}", status, err);
        return Err(format!("GCP IAM signBlob error: {}", err).into());
    }
    
    let sign_json: serde_json::Value = sign_resp.json().await?;
    println!("Sign Response OK. Payload: {:?}", sign_json);
    
    let signature = sign_json["signedBlob"].as_str().ok_or("No signedBlob in response")?.to_string();
    let key_id = sign_json["keyId"].as_str().ok_or("No keyId in response")?.to_string();
    
    Ok((sa_email.trim().to_string(), key_id, signature))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing GCP IAM signBlob ---");
    let test_payload = "test_payload_for_debugging";
    println!("Payload to sign: {}", test_payload);
    
    match sign_with_gcp_iam(test_payload).await {
        Ok((sa, key_id, sig)) => {
            println!("\nSUCCESS!");
            println!("Service Account: {}", sa);
            println!("Key ID: {}", key_id);
            println!("Signature: {}", sig);
        },
        Err(e) => {
            println!("\nFAILURE: {:?}", e);
        }
    }
    
    Ok(())
}
