fn main() {
    let pcr_str = "  sha256:\n    0 : 0x123\n    15: 0x456";
    let mut pcr_values = std::collections::HashMap::new();
    for line in pcr_str.lines() {
        if line.contains(':') && !line.trim().is_empty() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let idx = parts[0].trim_matches(|c: char| !c.is_numeric()).to_string();
                let val = parts[1].trim().to_string();
                if !idx.is_empty() && !val.is_empty() {
                    pcr_values.insert(idx, val);
                }
            }
        }
    }
    println!("{:?}", pcr_values);
}
