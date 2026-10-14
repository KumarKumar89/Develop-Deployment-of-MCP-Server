use serde::Serialize;
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Serialize, PartialEq)]
pub struct IndicatorAssessment {
    pub indicator_type: String,
    pub normalized: String,
    pub syntactically_valid: bool,
    pub assessment_scope: &'static str,
    pub recommended_follow_up: Vec<&'static str>,
}

/// Syntax-only validation. Never performs DNS, HTTP, or threat-intelligence lookups.
pub fn assess_indicator(kind: &str, raw: &str) -> Result<IndicatorAssessment, String> {
    let kind = kind.trim().to_ascii_lowercase();
    let value = raw.trim();

    if value.is_empty() {
        return Err("indicator must not be empty".to_string());
    }
    if value.len() > 2048 {
        return Err("indicator must not exceed 2048 bytes".to_string());
    }

    let (indicator_type, normalized) = match kind.as_str() {
        "ip" => {
            let parsed: IpAddr = value
                .parse()
                .map_err(|_| "indicator is not a valid IP address".to_string())?;
            ("ip".to_string(), parsed.to_string())
        }
        "domain" => {
            let domain = value.trim_end_matches('.').to_ascii_lowercase();
            if !is_valid_domain(&domain) {
                return Err("indicator is not a valid ASCII domain name".to_string());
            }
            ("domain".to_string(), domain)
        }
        "url" => {
            let mut parsed = Url::parse(value)
                .map_err(|_| "indicator is not a valid absolute URL".to_string())?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err("only HTTP and HTTPS URLs are accepted".to_string());
            }
            if parsed.host_str().is_none() {
                return Err("URL must contain a host".to_string());
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err("URLs containing embedded credentials are not accepted".to_string());
            }
            // Avoid echoing paths, query parameters, or fragments that may contain secrets.
            parsed.set_path("/");
            parsed.set_query(None);
            parsed.set_fragment(None);
            ("url".to_string(), parsed.to_string())
        }
        "sha256" => {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(
                    "SHA-256 indicator must contain exactly 64 hexadecimal characters".to_string(),
                );
            }
            ("sha256".to_string(), value.to_ascii_lowercase())
        }
        _ => return Err("kind must be one of: ip, domain, url, sha256".to_string()),
    };

    Ok(IndicatorAssessment {
        indicator_type,
        normalized,
        syntactically_valid: true,
        assessment_scope: "Syntax-only validation; not a maliciousness, reputation, reachability, or attribution verdict.",
        recommended_follow_up: vec![
            "Correlate with approved SIEM, EDR, DNS, proxy, and identity telemetry.",
            "Use an organization-approved threat-intelligence source when policy permits.",
            "Preserve supporting evidence and follow the incident-response runbook.",
        ],
    })
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.parse::<IpAddr>().is_ok() {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::assess_indicator;

    #[test]
    fn normalizes_ipv4() {
        let result = assess_indicator("ip", "  192.0.2.1  ").unwrap();
        assert_eq!(result.normalized, "192.0.2.1");
        assert_eq!(result.indicator_type, "ip");
        assert!(result.syntactically_valid);
    }

    #[test]
    fn normalizes_ipv6() {
        let result = assess_indicator("IP", "2001:0db8:0:0:0:0:0:1").unwrap();
        assert_eq!(result.normalized, "2001:db8::1");
        assert!(result.syntactically_valid);
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(assess_indicator("ip", "999.999.999.999").is_err());
        assert!(assess_indicator("ip", "not-an-ip").is_err());
    }

    #[test]
    fn normalizes_domain_case_and_trailing_dot() {
        let result = assess_indicator("domain", "ExAmPlE.COM.").unwrap();
        assert_eq!(result.normalized, "example.com");
    }

    #[test]
    fn rejects_ip_as_domain() {
        assert!(assess_indicator("domain", "192.0.2.1").is_err());
    }

    #[test]
    fn rejects_empty_or_oversized() {
        assert!(assess_indicator("ip", "").is_err());
        assert!(assess_indicator("ip", " ").is_err());
        let big = "a".repeat(2049);
        assert!(assess_indicator("domain", &big).is_err());
    }

    #[test]
    fn rejects_non_http_url_scheme() {
        assert!(assess_indicator("url", "file:///etc/passwd").is_err());
        assert!(assess_indicator("url", "ftp://example.com/file").is_err());
        assert!(assess_indicator("url", "javascript:alert(1)").is_err());
    }

    #[test]
    fn redacts_url_path_query_and_fragment() {
        let result = assess_indicator(
            "url",
            "https://example.com/user/secret?token=do-not-echo#top",
        )
        .unwrap();
        assert_eq!(result.normalized, "https://example.com/");
        assert!(!result.normalized.contains("do-not-echo"));
    }

    #[test]
    fn rejects_url_embedded_credentials() {
        assert!(assess_indicator("url", "https://user:pass@example.com/path").is_err());
    }

    #[test]
    fn validates_sha256_shape() {
        let digest = "A".repeat(64);
        let result = assess_indicator("sha256", &digest).unwrap();
        assert_eq!(result.normalized, "a".repeat(64));
        assert!(assess_indicator("sha256", "bad-hash").is_err());
        assert!(assess_indicator("sha256", &"a".repeat(63)).is_err());
        assert!(assess_indicator("sha256", &"g".repeat(64)).is_err());
    }

    #[test]
    fn rejects_unknown_indicator_kind() {
        assert!(assess_indicator("command", "whoami").is_err());
        assert!(assess_indicator("email", "a@b.com").is_err());
    }
}
