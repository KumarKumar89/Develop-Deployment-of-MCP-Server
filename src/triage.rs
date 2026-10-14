use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AlertArgs {
    /// Severity reported by the upstream alert: critical, high, medium, or low.
    pub severity: String,
    /// Short alert category such as suspicious-login or malware-detection.
    pub alert_type: String,
    /// Brief analyst-safe description. Maximum 4000 bytes; the server does not persist it.
    pub summary: String,
    /// Optional observed indicators. Maximum 50 entries, each no longer than 512 bytes.
    #[serde(default)]
    pub indicators: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct AlertTriage {
    pub priority: &'static str,
    pub severity: String,
    pub alert_type: String,
    pub indicator_count: usize,
    pub recommended_actions: Vec<&'static str>,
    pub human_approval_required_for_containment: bool,
    pub assessment_scope: &'static str,
}

pub fn triage_alert(args: AlertArgs) -> Result<AlertTriage, String> {
    let severity = args.severity.trim().to_ascii_lowercase();
    if args.alert_type.trim().is_empty() || args.alert_type.len() > 128 {
        return Err("alert_type must contain 1 to 128 bytes".to_string());
    }
    if args.summary.trim().is_empty() || args.summary.len() > 4000 {
        return Err("summary must contain 1 to 4000 bytes".to_string());
    }
    if args.indicators.len() > 50 || args.indicators.iter().any(|item| item.len() > 512) {
        return Err("indicators are limited to 50 entries of at most 512 bytes each".to_string());
    }

    let (priority, actions) = match severity.as_str() {
        "critical" => (
            "P1",
            vec![
                "Activate the incident-response process and notify the on-call security lead.",
                "Preserve relevant endpoint, identity, network, cloud, and SIEM evidence with timestamps.",
                "Correlate the alert with independent telemetry and determine scope and business impact.",
                "Consider containment only through an approved runbook with authorized human approval.",
            ],
        ),
        "high" => (
            "P2",
            vec![
                "Assign promptly to the security operations team and validate the alert source.",
                "Correlate identity, endpoint, network, and cloud events to establish scope.",
                "Preserve evidence and follow the documented escalation and containment policy.",
            ],
        ),
        "medium" => (
            "P3",
            vec![
                "Validate the detection against baseline behavior and corroborating telemetry.",
                "Enrich indicators only with approved data sources and applicable handling rules.",
                "Document findings and escalate if evidence increases severity or expands scope.",
            ],
        ),
        "low" => (
            "P4",
            vec![
                "Review context and confirm whether the activity is expected or a known false positive.",
                "Record the rationale and monitor for repeated or correlated events.",
                "Reassess severity if additional evidence or business impact emerges.",
            ],
        ),
        _ => return Err("severity must be one of: critical, high, medium, low".to_string()),
    };

    Ok(AlertTriage {
        priority,
        severity,
        alert_type: args.alert_type.trim().to_string(),
        indicator_count: args.indicators.len(),
        recommended_actions: actions,
        human_approval_required_for_containment: true,
        assessment_scope: "Guidance based only on caller-supplied metadata. No live telemetry is queried and no response action is executed.",
    })
}

#[cfg(test)]
mod tests {
    use super::{triage_alert, AlertArgs};

    fn sample(severity: &str) -> AlertArgs {
        AlertArgs {
            severity: severity.to_string(),
            alert_type: "suspicious-login".to_string(),
            summary: "Multiple unusual sign-in attempts".to_string(),
            indicators: vec!["203.0.113.7".to_string()],
        }
    }

    #[test]
    fn critical_alert_becomes_p1_and_requires_approval() {
        let result = triage_alert(sample("critical")).unwrap();
        assert_eq!(result.priority, "P1");
        assert!(result.human_approval_required_for_containment);
        assert_eq!(result.indicator_count, 1);
    }

    #[test]
    fn high_medium_low_priorities() {
        assert_eq!(triage_alert(sample("high")).unwrap().priority, "P2");
        assert_eq!(triage_alert(sample("medium")).unwrap().priority, "P3");
        assert_eq!(triage_alert(sample("low")).unwrap().priority, "P4");
    }

    #[test]
    fn severity_is_case_insensitive() {
        assert_eq!(triage_alert(sample("CRITICAL")).unwrap().priority, "P1");
        assert_eq!(triage_alert(sample(" High ")).unwrap().priority, "P2");
    }

    #[test]
    fn rejects_unknown_severity() {
        assert!(triage_alert(sample("emergency")).is_err());
        assert!(triage_alert(sample("")).is_err());
    }

    #[test]
    fn rejects_empty_alert_type_or_summary() {
        let mut args = sample("high");
        args.alert_type = String::new();
        assert!(triage_alert(args).is_err());

        let mut args = sample("high");
        args.summary = "   ".to_string();
        assert!(triage_alert(args).is_err());
    }

    #[test]
    fn rejects_oversized_indicator_collection() {
        let mut args = sample("high");
        args.indicators = vec!["x".to_string(); 51];
        assert!(triage_alert(args).is_err());
    }

    #[test]
    fn accepts_empty_indicators_by_default() {
        let args = AlertArgs {
            severity: "low".to_string(),
            alert_type: "info".to_string(),
            summary: "noise".to_string(),
            indicators: vec![],
        };
        let result = triage_alert(args).unwrap();
        assert_eq!(result.indicator_count, 0);
        assert_eq!(result.priority, "P4");
    }
}
