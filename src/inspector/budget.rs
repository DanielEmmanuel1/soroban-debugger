use crossterm::style::{Color, Stylize};
use soroban_env_host::Host;

/// Tracks resource usage (CPU and memory budget)
pub struct BudgetInspector;

impl BudgetInspector {
    /// Get CPU instruction usage from host
    pub fn get_cpu_usage(host: &Host) -> BudgetInfo {
        let budget = host.budget_cloned();
        let cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0);
        let cpu_remaining = budget.get_cpu_insns_remaining().unwrap_or(0);
        let mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0);
        let mem_remaining = budget.get_mem_bytes_remaining().unwrap_or(0);

        BudgetInfo {
            cpu_instructions: cpu_consumed,
            cpu_limit: cpu_consumed.saturating_add(cpu_remaining),
            memory_bytes: mem_consumed,
            memory_limit: mem_consumed.saturating_add(mem_remaining),
        }
    }

    /// Display budget information with warnings
    pub fn display(host: &Host) {
        let info = Self::get_cpu_usage(host);

        println!("Resource Budget:");
        println!(
            "  CPU: {} / {} ({:.1}%)",
            info.cpu_instructions,
            info.cpu_limit,
            info.cpu_percentage()
        );
        println!(
            "  Memory: {} / {} bytes ({:.1}%)",
            info.memory_bytes,
            info.memory_limit,
            info.memory_percentage()
        );

        let warnings = Self::check_thresholds(&info);
        for warning in warnings {
            let color = match warning.severity {
                Severity::Yellow => Color::Yellow,
                Severity::Red => Color::Red,
                Severity::Critical => Color::DarkRed,
            };

            let prefix = match warning.severity {
                Severity::Yellow => "[WARNING]",
                Severity::Red => "[ALERT]",
                Severity::Critical => "[CRITICAL]",
            };

            println!(
                "  {} {} usage at {:.1}%",
                prefix.with(color),
                warning.resource,
                warning.percentage
            );

            if let Some(suggestion) = warning.suggestion {
                println!("    Suggestion: {}", suggestion.italic());
            }
        }
    }

    /// Check if usage exceeds defined thresholds
    pub fn check_thresholds(info: &BudgetInfo) -> Vec<BudgetWarning> {
        let mut warnings = Vec::new();

        // Check CPU
        let cpu_pct = info.cpu_percentage();
        if let Some(warning) = Self::create_warning("CPU", cpu_pct) {
            warnings.push(warning);
        }

        // Check Memory
        let mem_pct = info.memory_percentage();
        if let Some(warning) = Self::create_warning("Memory", mem_pct) {
            warnings.push(warning);
        }

        warnings
    }

    fn create_warning(resource: &str, percentage: f64) -> Option<BudgetWarning> {
        if percentage >= 90.0 {
            Some(BudgetWarning {
                resource: resource.to_string(),
                percentage,
                severity: Severity::Critical,
                suggestion: Some(format!(
                    "High {} usage detected. Consider optimizing contract logic or reducing data complexity.",
                    resource
                )),
            })
        } else if percentage >= 85.0 {
            Some(BudgetWarning {
                resource: resource.to_string(),
                percentage,
                severity: Severity::Red,
                suggestion: None,
            })
        } else if percentage >= 70.0 {
            Some(BudgetWarning {
                resource: resource.to_string(),
                percentage,
                severity: Severity::Yellow,
                suggestion: None,
            })
        } else {
            None
        }
    }
}

/// Severity level for budget warnings
pub enum Severity {
    Yellow,
    Red,
    Critical,
}

/// Represents a warning about resource usage
pub struct BudgetWarning {
    pub resource: String,
    pub percentage: f64,
    pub severity: Severity,
    pub suggestion: Option<String>,
}

/// Budget information snapshot
#[derive(Debug, Clone)]
pub struct BudgetInfo {
    pub cpu_instructions: u64,
    pub cpu_limit: u64,
    pub memory_bytes: u64,
    pub memory_limit: u64,
}

impl BudgetInfo {
    /// Calculate CPU usage percentage
    pub fn cpu_percentage(&self) -> f64 {
        if self.cpu_limit == 0 {
            0.0
        } else {
            (self.cpu_instructions as f64 / self.cpu_limit as f64) * 100.0
        }
    }

    /// Calculate memory usage percentage
    pub fn memory_percentage(&self) -> f64 {
        if self.memory_limit == 0 {
            0.0
        } else {
            (self.memory_bytes as f64 / self.memory_limit as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_percentage_calculation() {
        let info = BudgetInfo {
            cpu_instructions: 50,
            cpu_limit: 100,
            memory_bytes: 25,
            memory_limit: 100,
        };
        assert_eq!(info.cpu_percentage(), 50.0);
        assert_eq!(info.memory_percentage(), 25.0);
    }

    #[test]
    fn test_check_thresholds_none() {
        let info = BudgetInfo {
            cpu_instructions: 50,
            cpu_limit: 100,
            memory_bytes: 50,
            memory_limit: 100,
        };
        let warnings = BudgetInspector::check_thresholds(&info);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_thresholds_yellow() {
        let info = BudgetInfo {
            cpu_instructions: 75,
            cpu_limit: 100,
            memory_bytes: 50,
            memory_limit: 100,
        };
        let warnings = BudgetInspector::check_thresholds(&info);
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0].severity, Severity::Yellow));
    }

    #[test]
    fn test_check_thresholds_red() {
        let info = BudgetInfo {
            cpu_instructions: 86,
            cpu_limit: 100,
            memory_bytes: 50,
            memory_limit: 100,
        };
        let warnings = BudgetInspector::check_thresholds(&info);
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0].severity, Severity::Red));
    }

    #[test]
    fn test_check_thresholds_critical() {
        let info = BudgetInfo {
            cpu_instructions: 91,
            cpu_limit: 100,
            memory_bytes: 50,
            memory_limit: 100,
        };
        let warnings = BudgetInspector::check_thresholds(&info);
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0].severity, Severity::Critical));
        assert!(warnings[0].suggestion.is_some());
    }
}
