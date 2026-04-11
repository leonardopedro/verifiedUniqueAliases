use instant_acme::{Account, NewAccount, ExternalAccountKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = "1f256eb7b209f4dea7424af3452d6e80";
    let b64_hmac = "dkhbUYrIBc3O5ncsQ2eInJtbGcu9j5k2GCJJPMXS3BC6XtCsbGXT8K3JPW0jd_pYBmLAgu3kXjYtlnwL9r4ZvEU";
    
    let hmac_bytes = URL_SAFE_NO_PAD.decode(b64_hmac.trim())?;
    let eab = ExternalAccountKey::new(key_id.to_string(), &hmac_bytes);
    let acme_url = "https://dv.acme-v02.api.pki.goog/directory";
    
    println!("Registering account with Google Public CA...");
    let (_, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &["mailto:admin@airma.de"],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme_url.to_owned(),
            Some(&eab),
        )
        .await?;
        
    println!("SUCCESS! Account registered.");
    println!("Account Credentials JSON:");
    println!("{}", serde_json::to_string_pretty(&credentials)?);
    
    Ok(())
}
