use crate::error::{AegisError, Result};
use crate::metrics::METRICS;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    AttackSummary,
    Compliance,
    Performance,
    Incident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStandard {
    Gdpr,
    PciDss,
    Hipaa,
}

impl std::fmt::Display for ComplianceStandard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStandard::Gdpr => write!(f, "GDPR"),
            ComplianceStandard::PciDss => write!(f, "PCI-DSS"),
            ComplianceStandard::Hipaa => write!(f, "HIPAA"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub report_type: ReportType,
    pub generated_at: String,
    pub title: String,
    pub summary: String,
    pub sections: Vec<ReportSection>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub heading: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub rows: Vec<HashMap<String, serde_json::Value>>,
}

impl Report {
    fn new(report_type: ReportType, title: &str) -> Self {
        Report {
            report_type,
            generated_at: chrono::Utc::now().to_rfc3339(),
            title: title.to_string(),
            summary: String::new(),
            sections: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn add_section(&mut self, section: ReportSection) {
        self.sections.push(section);
    }

    fn with_summary(mut self, summary: &str) -> Self {
        self.summary = summary.to_string();
        self
    }

    fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ReportGenerator;

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator {
    pub fn new() -> Self {
        ReportGenerator
    }
}

pub fn generate_attack_report() -> Result<Report> {
    let stats = METRICS.get_attack_stats();
    let violations = METRICS.get_violations();
    let total_attacks: u64 = stats.iter().map(|s| s.count).sum();

    let mut report = Report::new(ReportType::AttackSummary, "Attack Summary Report")
        .with_summary(&format!(
            "Total attacks blocked: {} across {} distinct attack types",
            total_attacks,
            stats.len()
        ))
        .with_metadata("total_attacks", &total_attacks.to_string())
        .with_metadata("attack_types", &stats.len().to_string())
        .with_metadata(
            "active_connections",
            &METRICS.get_active_connections().to_string(),
        );

    let mut type_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    for stat in &stats {
        let mut row = HashMap::new();
        row.insert(
            "attack_type".to_string(),
            serde_json::Value::String(stat.attack_type.clone()),
        );
        row.insert(
            "count".to_string(),
            serde_json::Value::Number(stat.count.into()),
        );
        row.insert(
            "severity".to_string(),
            serde_json::Value::String(stat.severity.clone()),
        );
        type_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "Attacks by Type".to_string(),
        fields: {
            let mut f = HashMap::new();
            f.insert(
                "total_blocked".to_string(),
                serde_json::Value::Number(total_attacks.into()),
            );
            f.insert(
                "unique_types".to_string(),
                serde_json::Value::Number((stats.len() as u64).into()),
            );
            f
        },
        rows: type_rows,
    });

    let mut source_map: HashMap<String, u64> = HashMap::new();
    for v in &violations {
        *source_map.entry(v.source_ip.clone()).or_insert(0) += 1;
    }
    let mut source_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    let mut sorted_sources: Vec<_> = source_map.iter().collect();
    sorted_sources.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, count) in sorted_sources.iter().take(50) {
        let mut row = HashMap::new();
        row.insert(
            "source_ip".to_string(),
            serde_json::Value::String((*ip).clone()),
        );
        row.insert(
            "attack_count".to_string(),
            serde_json::Value::Number((**count).into()),
        );
        source_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "Attacks by Source IP".to_string(),
        fields: {
            let mut f = HashMap::new();
            f.insert(
                "unique_sources".to_string(),
                serde_json::Value::Number((source_map.len() as u64).into()),
            );
            f
        },
        rows: source_rows,
    });

    let severity_counts = {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for v in &violations {
            *counts.entry(v.severity.clone()).or_insert(0) += 1;
        }
        let mut rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
        for (sev, count) in counts.iter() {
            let mut row = HashMap::new();
            row.insert(
                "severity".to_string(),
                serde_json::Value::String(sev.clone()),
            );
            row.insert(
                "count".to_string(),
                serde_json::Value::Number((*count).into()),
            );
            rows.push(row);
        }
        rows
    };

    report.add_section(ReportSection {
        heading: "Attacks by Severity".to_string(),
        fields: HashMap::new(),
        rows: severity_counts,
    });

    Ok(report)
}

pub fn generate_compliance_report(standard: &ComplianceStandard) -> Result<Report> {
    let violations = METRICS.get_violations();
    let title = format!("{} Compliance Report", standard);
    let mut report = Report::new(ReportType::Compliance, &title)
        .with_summary(&format!(
            "{} compliance report covering {} security events",
            standard,
            violations.len()
        ))
        .with_metadata("standard", &standard.to_string())
        .with_metadata(
            "period_start",
            &chrono::Utc::now().format("%Y-%m-%d").to_string(),
        );

    let common_fields = {
        let mut f = HashMap::new();
        f.insert(
            "organization".to_string(),
            serde_json::Value::String("Aegis WAF Deployment".into()),
        );
        f.insert(
            "report_date".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
        f.insert(
            "total_events".to_string(),
            serde_json::Value::Number((violations.len() as u64).into()),
        );
        f.insert(
            "compliance_standard".to_string(),
            serde_json::Value::String(standard.to_string()),
        );
        f
    };

    report.add_section(ReportSection {
        heading: "General Information".to_string(),
        fields: common_fields,
        rows: Vec::new(),
    });

    match standard {
        ComplianceStandard::Gdpr => {
            add_gdpr_sections(&mut report, &violations);
        }
        ComplianceStandard::PciDss => {
            add_pci_sections(&mut report, &violations);
        }
        ComplianceStandard::Hipaa => {
            add_hipaa_sections(&mut report, &violations);
        }
    }

    Ok(report)
}

fn add_gdpr_sections(report: &mut Report, violations: &[crate::metrics::ViolationRecord]) {
    let mut fields = HashMap::new();
    fields.insert(
        "data_processing_lawfulness".to_string(),
        serde_json::Value::String(
            "Data processed for security purposes under legitimate interest".into(),
        ),
    );
    fields.insert(
        "data_minimization".to_string(),
        serde_json::Value::String(
            "Only security-relevant data collected (IP, timestamp, attack type)".into(),
        ),
    );
    fields.insert(
        "data_retention".to_string(),
        serde_json::Value::String(
            "Security logs retained for 90 days per incident response requirements".into(),
        ),
    );
    fields.insert(
        "right_to_erasure".to_string(),
        serde_json::Value::String("Supported via data subject request workflow".into()),
    );
    fields.insert(
        "breach_notification".to_string(),
        serde_json::Value::String("Automated alerts for qualifying security incidents".into()),
    );

    report.add_section(ReportSection {
        heading: "GDPR - Article 5 (Data Processing Principles)".to_string(),
        fields,
        rows: Vec::new(),
    });

    let mut rights_fields = HashMap::new();
    rights_fields.insert(
        "right_of_access".to_string(),
        serde_json::Value::String("Implemented".into()),
    );
    rights_fields.insert(
        "right_to_rectification".to_string(),
        serde_json::Value::String("Implemented".into()),
    );
    rights_fields.insert(
        "right_to_erasure".to_string(),
        serde_json::Value::String("Implemented".into()),
    );
    rights_fields.insert(
        "right_to_restrict".to_string(),
        serde_json::Value::String("Implemented".into()),
    );
    rights_fields.insert(
        "right_to_portability".to_string(),
        serde_json::Value::String("Not applicable - security data".into()),
    );
    rights_fields.insert(
        "right_to_object".to_string(),
        serde_json::Value::String("Implemented with legitimate interest override".into()),
    );

    report.add_section(ReportSection {
        heading: "GDPR - Data Subject Rights".to_string(),
        fields: rights_fields,
        rows: Vec::new(),
    });

    let mut incident_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    for v in violations.iter().take(100) {
        let mut row = HashMap::new();
        row.insert(
            "timestamp".to_string(),
            serde_json::Value::String(v.timestamp.clone()),
        );
        row.insert(
            "event_type".to_string(),
            serde_json::Value::String(v.attack_type.clone()),
        );
        row.insert(
            "severity".to_string(),
            serde_json::Value::String(v.severity.clone()),
        );
        row.insert(
            "personal_data_involved".to_string(),
            serde_json::Value::String("IP address only".into()),
        );
        row.insert(
            "notification_required".to_string(),
            serde_json::Value::String(
                if v.severity == "Critical" {
                    "Yes"
                } else {
                    "No"
                }
                .into(),
            ),
        );
        incident_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "GDPR - Article 33 (Breach Notification Assessment)".to_string(),
        fields: HashMap::new(),
        rows: incident_rows,
    });
}

fn add_pci_sections(report: &mut Report, violations: &[crate::metrics::ViolationRecord]) {
    let mut fields = HashMap::new();
    fields.insert(
        "requirement_6.6".to_string(),
        serde_json::Value::String("WAF deployed to protect web applications".into()),
    );
    fields.insert(
        "firewall_configuration".to_string(),
        serde_json::Value::String("Active protection with rule-based filtering".into()),
    );
    fields.insert(
        "change_detection".to_string(),
        serde_json::Value::String("All configuration changes logged".into()),
    );
    fields.insert(
        "access_control".to_string(),
        serde_json::Value::String("Role-based access to WAF management".into()),
    );

    report.add_section(ReportSection {
        heading: "PCI-DSS - Requirement 6 (Secure Systems)".to_string(),
        fields,
        rows: Vec::new(),
    });

    let mut audit_fields = HashMap::new();
    audit_fields.insert(
        "log_collection".to_string(),
        serde_json::Value::String("Audit logs collected for all security events".into()),
    );
    audit_fields.insert(
        "log_protection".to_string(),
        serde_json::Value::String("Logs protected from unauthorized modification".into()),
    );
    audit_fields.insert(
        "log_review".to_string(),
        serde_json::Value::String("Automated review via threat detection system".into()),
    );
    audit_fields.insert(
        "retention_period".to_string(),
        serde_json::Value::String("12 months per PCI-DSS requirement 10.7".into()),
    );

    report.add_section(ReportSection {
        heading: "PCI-DSS - Requirement 10 (Logging & Monitoring)".to_string(),
        fields: audit_fields,
        rows: Vec::new(),
    });

    let mut incident_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    for v in violations.iter().take(100) {
        let mut row = HashMap::new();
        row.insert(
            "timestamp".to_string(),
            serde_json::Value::String(v.timestamp.clone()),
        );
        row.insert(
            "attack_type".to_string(),
            serde_json::Value::String(v.attack_type.clone()),
        );
        row.insert(
            "severity".to_string(),
            serde_json::Value::String(v.severity.clone()),
        );
        row.insert(
            "source_ip".to_string(),
            serde_json::Value::String(v.source_ip.clone()),
        );
        row.insert(
            "action_taken".to_string(),
            serde_json::Value::String(v.action.clone()),
        );
        row.insert(
            "pci_relevant".to_string(),
            serde_json::Value::String("Yes - web application attack".into()),
        );
        incident_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "PCI-DSS - Security Events".to_string(),
        fields: HashMap::new(),
        rows: incident_rows,
    });
}

fn add_hipaa_sections(report: &mut Report, violations: &[crate::metrics::ViolationRecord]) {
    let mut fields = HashMap::new();
    fields.insert(
        "security_rule".to_string(),
        serde_json::Value::String("Administrative, physical, and technical safeguards".into()),
    );
    fields.insert(
        "technical_safeguards".to_string(),
        serde_json::Value::String("Access control, audit controls, integrity controls".into()),
    );
    fields.insert(
        "encryption".to_string(),
        serde_json::Value::String("TLS 1.2+ for all data in transit".into()),
    );
    fields.insert(
        "risk_analysis".to_string(),
        serde_json::Value::String("Continuous threat monitoring and risk assessment".into()),
    );

    report.add_section(ReportSection {
        heading: "HIPAA - Security Rule (45 CFR Part 164)".to_string(),
        fields,
        rows: Vec::new(),
    });

    let mut audit_fields = HashMap::new();
    audit_fields.insert(
        "audit_controls".to_string(),
        serde_json::Value::String(
            "Hardware/software mechanisms to record and examine system activity".into(),
        ),
    );
    audit_fields.insert(
        "access_logging".to_string(),
        serde_json::Value::String("All access attempts logged with timestamp and source".into()),
    );
    audit_fields.insert(
        "integrity_controls".to_string(),
        serde_json::Value::String("Log integrity verification enabled".into()),
    );
    audit_fields.insert(
        "incident_response".to_string(),
        serde_json::Value::String("Automated incident detection and response".into()),
    );

    report.add_section(ReportSection {
        heading: "HIPAA - Audit Controls".to_string(),
        fields: audit_fields,
        rows: Vec::new(),
    });

    let mut breach_fields = HashMap::new();
    breach_fields.insert(
        "breach_detection".to_string(),
        serde_json::Value::String("Real-time detection of unauthorized access".into()),
    );
    breach_fields.insert(
        "notification_capability".to_string(),
        serde_json::Value::String("Automated notification system for qualifying breaches".into()),
    );
    breach_fields.insert(
        "risk_assessment".to_string(),
        serde_json::Value::String("Per-incident risk scoring and assessment".into()),
    );

    report.add_section(ReportSection {
        heading: "HIPAA - Breach Notification Rule".to_string(),
        fields: breach_fields,
        rows: Vec::new(),
    });

    let mut incident_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    for v in violations.iter().take(100) {
        let mut row = HashMap::new();
        row.insert(
            "timestamp".to_string(),
            serde_json::Value::String(v.timestamp.clone()),
        );
        row.insert(
            "event_type".to_string(),
            serde_json::Value::String(v.attack_type.clone()),
        );
        row.insert(
            "severity_level".to_string(),
            serde_json::Value::String(v.severity.clone()),
        );
        row.insert(
            "source".to_string(),
            serde_json::Value::String(v.source_ip.clone()),
        );
        row.insert(
            "phi_accessed".to_string(),
            serde_json::Value::String("No PHI involved - WAF layer".into()),
        );
        row.insert(
            "breach_determination".to_string(),
            serde_json::Value::String("Not a breach - attack blocked".into()),
        );
        incident_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "HIPAA - Incident Log".to_string(),
        fields: HashMap::new(),
        rows: incident_rows,
    });
}

pub fn generate_performance_report() -> Result<Report> {
    let mut report = Report::new(ReportType::Performance, "Performance Report")
        .with_summary("System performance metrics and resource utilization")
        .with_metadata(
            "requests_total",
            &METRICS.get_requests_per_sec().to_string(),
        )
        .with_metadata(
            "bytes_processed",
            &METRICS.get_bytes_processed().to_string(),
        )
        .with_metadata(
            "active_connections",
            &METRICS.get_active_connections().to_string(),
        );

    let mut throughput_fields = HashMap::new();
    throughput_fields.insert(
        "total_requests".to_string(),
        serde_json::Value::Number(
            serde_json::Number::from_f64(METRICS.get_requests_per_sec()).unwrap_or(0.into()),
        ),
    );
    throughput_fields.insert(
        "bytes_processed".to_string(),
        serde_json::Value::Number(
            serde_json::Number::from_f64(METRICS.get_bytes_processed() as f64).unwrap_or(0.into()),
        ),
    );
    throughput_fields.insert(
        "active_connections".to_string(),
        serde_json::Value::Number(
            serde_json::Number::from_f64(METRICS.get_active_connections() as f64)
                .unwrap_or(0.into()),
        ),
    );

    report.add_section(ReportSection {
        heading: "Throughput Metrics".to_string(),
        fields: throughput_fields,
        rows: Vec::new(),
    });

    let mut resource_fields = HashMap::new();
    resource_fields.insert(
        "uptime_seconds".to_string(),
        serde_json::Value::Number(METRICS.get_uptime_secs().into()),
    );
    resource_fields.insert(
        "system_status".to_string(),
        serde_json::Value::String("operational".into()),
    );

    report.add_section(ReportSection {
        heading: "Resource Utilization".to_string(),
        fields: resource_fields,
        rows: Vec::new(),
    });

    let mut latency_data: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    let mut row = HashMap::new();
    row.insert(
        "metric".to_string(),
        serde_json::Value::String("avg_latency_ms".into()),
    );
    row.insert(
        "value".to_string(),
        serde_json::Value::Number(serde_json::Number::from_f64(0.0).unwrap()),
    );
    latency_data.push(row);

    report.add_section(ReportSection {
        heading: "Latency Distribution".to_string(),
        fields: HashMap::new(),
        rows: latency_data,
    });

    Ok(report)
}

pub fn generate_incident_report() -> Result<Report> {
    let violations = METRICS.get_violations();

    let mut report = Report::new(ReportType::Incident, "Incident Report")
        .with_summary(&format!(
            "Detailed incident report covering {} security violations",
            violations.len()
        ))
        .with_metadata("incident_count", &violations.len().to_string())
        .with_metadata("report_period", "current");

    let mut severity_map: HashMap<String, u64> = HashMap::new();
    for v in &violations {
        *severity_map.entry(v.severity.clone()).or_insert(0) += 1;
    }

    let mut summary_fields = HashMap::new();
    summary_fields.insert(
        "total_incidents".to_string(),
        serde_json::Value::Number((violations.len() as u64).into()),
    );
    summary_fields.insert(
        "critical_incidents".to_string(),
        serde_json::Value::Number(severity_map.get("Critical").copied().unwrap_or(0).into()),
    );
    summary_fields.insert(
        "high_incidents".to_string(),
        serde_json::Value::Number(severity_map.get("High").copied().unwrap_or(0).into()),
    );
    summary_fields.insert(
        "medium_incidents".to_string(),
        serde_json::Value::Number(severity_map.get("Medium").copied().unwrap_or(0).into()),
    );
    summary_fields.insert(
        "low_incidents".to_string(),
        serde_json::Value::Number(severity_map.get("Low").copied().unwrap_or(0).into()),
    );

    report.add_section(ReportSection {
        heading: "Incident Summary".to_string(),
        fields: summary_fields,
        rows: Vec::new(),
    });

    let mut incident_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    for (i, v) in violations.iter().enumerate() {
        let mut row = HashMap::new();
        row.insert(
            "incident_id".to_string(),
            serde_json::Value::Number(((i + 1) as u64).into()),
        );
        row.insert(
            "timestamp".to_string(),
            serde_json::Value::String(v.timestamp.clone()),
        );
        row.insert(
            "attack_type".to_string(),
            serde_json::Value::String(v.attack_type.clone()),
        );
        row.insert(
            "severity".to_string(),
            serde_json::Value::String(v.severity.clone()),
        );
        row.insert(
            "source_ip".to_string(),
            serde_json::Value::String(v.source_ip.clone()),
        );
        row.insert(
            "details".to_string(),
            serde_json::Value::String(v.details.clone()),
        );
        row.insert(
            "action_taken".to_string(),
            serde_json::Value::String(v.action.clone()),
        );
        row.insert("resolved".to_string(), serde_json::Value::Bool(true));
        incident_rows.push(row);
    }

    report.add_section(ReportSection {
        heading: "Incident Details".to_string(),
        fields: HashMap::new(),
        rows: incident_rows,
    });

    Ok(report)
}

pub fn export_report(report: &Report, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Json => serde_json::to_string_pretty(report).map_err(AegisError::from),
        ReportFormat::Csv => export_csv(report),
    }
}

fn export_csv(report: &Report) -> Result<String> {
    let mut output = String::new();

    output.push_str(&format!("Report: {}\n", report.title));
    output.push_str(&format!("Type: {:?}\n", report.report_type));
    output.push_str(&format!("Generated: {}\n", report.generated_at));
    output.push_str(&format!("Summary: {}\n\n", report.summary));

    for section in &report.sections {
        output.push_str(&format!("=== {} ===\n", section.heading));

        if !section.fields.is_empty() {
            let field_names: Vec<&String> = section.fields.keys().collect();
            let mut sorted_names = field_names.clone();
            sorted_names.sort();
            for name in &sorted_names {
                let value = csv_escape_value(&section.fields[*name]);
                output.push_str(&format!("{}, {}\n", csv_escape(name), value));
            }
            output.push('\n');
        }

        if !section.rows.is_empty() {
            let mut all_columns: Vec<String> = Vec::new();
            for row in &section.rows {
                for col in row.keys() {
                    if !all_columns.contains(col) {
                        all_columns.push(col.clone());
                    }
                }
            }
            all_columns.sort();

            output.push_str(
                &all_columns
                    .iter()
                    .map(|c| csv_escape(c))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            output.push('\n');

            for row in &section.rows {
                let values: Vec<String> = all_columns
                    .iter()
                    .map(|col| row.get(col).map(csv_escape_value).unwrap_or_default())
                    .collect();
                output.push_str(&values.join(", "));
                output.push('\n');
            }
            output.push('\n');
        }
    }

    Ok(output)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_escape_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => csv_escape(s),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => csv_escape(&other.to_string()),
    }
}

pub fn export_to_file(report: &Report, format: ReportFormat, path: &Path) -> Result<()> {
    let content = export_report(report, format)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, &content)?;

    tracing::info!(
        "Report exported to {} in {:?} format",
        path.display(),
        format
    );

    Ok(())
}
