// SwitchGate kPerf - Fast Domain & URL Classifier
// Performs fast domain categorization and provides root domain extraction.

pub fn categorize_domain(domain: &str) -> &'static str {
    let d = domain.to_lowercase();
    if d.contains("youtube") || d.contains("netflix") || d.contains("twitch") || d.contains("googlevideo") || d.contains("ytimg") || d.contains("hotstar") || d.contains("primevideo") {
        "Video Streaming"
    } else if d.contains("instagram") || d.contains("facebook") || d.contains("tiktok") || d.contains("twitter") || d.contains("reddit") || d.contains("threads") || d.contains("snapchat") {
        "Social Media"
    } else if d.contains("google") || d.contains("bing") || d.contains("duckduckgo") || d.contains("yahoo") {
        "Search Engine"
    } else if d.contains("openai") || d.contains("anthropic") || d.contains("claude") || d.contains("chatgpt") || d.contains("gemini") {
        "Artificial Intelligence"
    } else if d.contains("roblox") || d.contains("steam") || d.contains("epicgames") || d.contains("ea.com") || d.contains("riotgames") {
        "Online Gaming"
    } else if d.contains("spotify") || d.contains("apple") || d.contains("soundcloud") || d.contains("music") {
        "Music Streaming"
    } else if d.contains("amazon") || d.contains("flipkart") || d.contains("aliexpress") || d.contains("ebay") {
        "E-Commerce"
    } else if d.contains("github") || d.contains("gitlab") || d.contains("stackoverflow") || d.contains("npm") || d.contains("pypi") {
        "Developer Tools"
    } else {
        "Web Service"
    }
}

pub fn extract_root_domain(fqdn: &str) -> String {
    let parts: Vec<&str> = fqdn.trim().split('.').collect();
    if parts.len() >= 2 {
        let last_two = &parts[parts.len() - 2..];
        last_two.join(".")
    } else {
        fqdn.to_string()
    }
}
