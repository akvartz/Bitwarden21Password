//! Warnings and conversion reporting.
//!
//! Conversions between formats are rarely 1:1. Instead of silently dropping
//! data, every importer/exporter records what could not be represented and
//! where it went instead, and the CLI prints the report at the end.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Data was preserved but relocated (e.g. custom field moved into notes).
    Info,
    /// Data was partially lost or degraded.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Note {
    pub severity: Severity,
    /// Item title or record number the note refers to, if any.
    pub context: Option<String>,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub notes: Vec<Note>,
}

impl Report {
    pub fn new() -> Self {
        Report::default()
    }

    pub fn info(&mut self, context: Option<&str>, message: impl Into<String>) {
        self.push(Severity::Info, context, message);
    }

    pub fn warn(&mut self, context: Option<&str>, message: impl Into<String>) {
        self.push(Severity::Warning, context, message);
    }

    fn push(&mut self, severity: Severity, context: Option<&str>, message: impl Into<String>) {
        self.notes.push(Note {
            severity,
            context: context.map(|c| c.to_string()),
            message: message.into(),
        });
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.notes.iter().filter(|n| n.severity == severity).count()
    }

    /// Render the report to stderr-friendly text. Returns None when empty.
    pub fn render(&self) -> Option<String> {
        if self.notes.is_empty() {
            return None;
        }
        let mut out = String::new();
        for note in &self.notes {
            match &note.context {
                Some(c) => out.push_str(&format!("[{}] {}: {}\n", note.severity, c, note.message)),
                None => out.push_str(&format!("[{}] {}\n", note.severity, note.message)),
            }
        }
        Some(out)
    }
}
