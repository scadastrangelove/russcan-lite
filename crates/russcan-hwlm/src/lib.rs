//! Литеральные движки (Ф2): noodle (один литерал), FDR, Teddy.
//!
//! Референс: `vectorscan/src/hwlm/`, `vectorscan/src/fdr/` @ a1c107e.
//! Таблицы движков приходят БАЙТАМИ из байткода (или из шима оракула в
//! тестах) — парсинг всегда bounds-checked, вход недоверенный.

pub mod fdr;
pub mod noodle;
pub mod teddy;

/// Управление сканом из колбэка (порт hwlmcb_rv_t).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCtl {
    Continue,
    Terminate,
}

/// Итог прогона движка: дошёл до конца или терминирован колбэком.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecResult {
    Completed,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwlmError {
    /// Байтов меньше, чем требует заголовок таблицы.
    Truncated,
    /// Поле таблицы с недопустимым значением.
    BadTable(&'static str),
}

impl core::fmt::Display for HwlmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HwlmError::Truncated => write!(f, "таблица движка обрезана"),
            HwlmError::BadTable(what) => write!(f, "битая таблица движка: {what}"),
        }
    }
}

impl std::error::Error for HwlmError {}
