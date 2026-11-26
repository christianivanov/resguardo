//! Policy decision from principal and findings (design document, "Política"; ADR 0012).
//!
//! Pure: no I/O and no clock. Principal, model and limits are checked by the server before
//! the body is scanned. This crate takes the action of each finding and limit flag, combines
//! them and returns one [`Decision`].
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use resguardo_core::{
    Action, BlockCode, Config, DataClass, Decision, Principal, ScanLimit, ScanReport,
};

/// The global actions. Built once from the configuration and only read afterwards, so one
/// instance can be shared by every request.
#[derive(Debug, Clone)]
pub struct Policy {
    actions: BTreeMap<DataClass, Action>,
    scan_limits: BTreeMap<ScanLimit, Action>,
}

impl Policy {
    pub fn new(
        actions: BTreeMap<DataClass, Action>,
        scan_limits: BTreeMap<ScanLimit, Action>,
    ) -> Self {
        Self {
            actions,
            scan_limits,
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(config.actions.clone(), config.scan_limits.clone())
    }

    /// The most restrictive action of all findings and limit flags wins (`Action` is ordered
    /// from `Allow` to `Block`). A block reports the first blocking class in `DataClass`
    /// order, or none when only a limit flag blocks.
    pub fn decide(&self, principal: &Principal, report: &ScanReport) -> Decision {
        let mut overall = Action::Allow;
        let mut blocking_class: Option<DataClass> = None;
        let mut spans = Vec::new();
        let mut flags = Vec::new();

        for finding in &report.findings {
            let action = self.finding_action(principal, finding.class);
            overall = overall.max(action);
            match action {
                Action::Block => {
                    blocking_class =
                        Some(blocking_class.map_or(finding.class, |c| c.min(finding.class)));
                }
                Action::Redact => spans.push(finding.clone()),
                Action::Flag => flags.push(finding.clone()),
                Action::Allow => {}
            }
        }
        for flag in &report.flags {
            overall = overall.max(self.limit_action(principal, flag.limit));
        }

        match overall {
            Action::Block => Decision::Block {
                code: BlockCode::SensitiveData,
                class: blocking_class,
            },
            Action::Redact => Decision::Redact { spans, flags },
            Action::Flag | Action::Allow => Decision::Allow { flags },
        }
    }

    /// The principal's action, then the global one; a class with neither blocks.
    fn finding_action(&self, principal: &Principal, class: DataClass) -> Action {
        principal
            .actions
            .get(&class)
            .or_else(|| self.actions.get(&class))
            .copied()
            .unwrap_or(Action::Block)
    }

    /// Only `flag` lets a limit through. A missing action, or one the configuration would
    /// have rejected (`allow`, `redact`), blocks.
    fn limit_action(&self, principal: &Principal, limit: ScanLimit) -> Action {
        match principal
            .scan_limits
            .get(&limit)
            .or_else(|| self.scan_limits.get(&limit))
        {
            Some(Action::Flag) => Action::Flag,
            _ => Action::Block,
        }
    }
}
