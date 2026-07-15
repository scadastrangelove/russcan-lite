//! Noodle: рантайм одного литерала — порт `hwlm/noodle_engine.cpp` @ a1c107e.
//!
//! Скан ищет ключевые байты (для single — последний байт литерала, для
//! double — пару у конца), подтверждение — сравнение по маске `msk`/`cmp`
//! последних `msk_len <= 8` байт литерала (LE-загрузка, `partial_load_u64a`).
//!
//! Реализация пока скалярная: кандидатный SIMD-скан (eqmask + итерация
//! лейнов, как в `noodle_engine_simd.hpp`) добавится при перф-проходе Ф2 —
//! множество отчётов от него не зависит, что и проверяет дифф-тест.

use crate::{ExecResult, HwlmError, ScanCtl};

/// `sizeof(struct noodTable)` (noodle_internal.h).
pub const NOOD_TABLE_SIZE: usize = 32;

/// Порт `struct noodTable`. Поля — из недоверенных байтов таблицы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoodTable {
    pub id: u32,
    pub msk: u64,
    pub cmp: u64,
    pub msk_len: u8,
    pub key_offset: u8,
    pub nocase: bool,
    pub single: bool,
    pub key0: u8,
    pub key1: u8,
}

impl NoodTable {
    /// Разбор из байтов таблицы (LE, layout по noodle_internal.h:
    /// id@0, msk@8, cmp@16, msk_len@24, key_offset@25, nocase@26,
    /// single@27, key0@28, key1@29).
    pub fn parse(bytes: &[u8]) -> Result<NoodTable, HwlmError> {
        if bytes.len() < NOOD_TABLE_SIZE {
            return Err(HwlmError::Truncated);
        }
        let u32le = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let u64le = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());

        let t = NoodTable {
            id: u32le(0),
            msk: u64le(8),
            cmp: u64le(16),
            msk_len: bytes[24],
            key_offset: bytes[25],
            nocase: bytes[26] != 0,
            single: bytes[27] != 0,
            key0: bytes[28],
            key1: bytes[29],
        };
        if t.msk_len == 0 || t.msk_len > 8 {
            return Err(HwlmError::BadTable("msk_len вне 1..=8"));
        }
        // Инварианты границ скана (см. scan_*): single репортит конец на
        // ключевом байте (key_offset == 1), double смотрит buf[p+1] и
        // требует key_offset >= 2.
        if t.single && t.key_offset != 1 {
            return Err(HwlmError::BadTable("single с key_offset != 1"));
        }
        if !t.single && t.key_offset < 2 {
            return Err(HwlmError::BadTable("double с key_offset < 2"));
        }
        if (t.key_offset as usize) > t.msk_len as usize + 1 {
            return Err(HwlmError::BadTable("key_offset за пределами маски"));
        }
        Ok(t)
    }

    /// Порт `noodExec` (block mode). `cb(end, id)`: `end` — индекс
    /// последнего байта матча.
    pub fn exec(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ExecResult {
        // scan(): в буфере короче msk_len литерала нет
        if buf.len().saturating_sub(start) < self.msk_len as usize {
            return ExecResult::Completed;
        }
        if self.single {
            self.scan_single(buf, start, cb)
        } else {
            self.scan_double(buf, start, cb)
        }
    }

    fn case_mask(nocase: bool) -> u8 {
        if nocase {
            0xdf
        } else {
            0xff
        }
    }

    fn scan_single(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ExecResult {
        // scanSingle: для небуквенного ключа регистр не трогаем
        let nocase = self.nocase && self.key0.is_ascii_alphabetic();
        let cm = Self::case_mask(nocase);
        let key = self.key0 & cm;
        // scanSingleMain: кандидаты с позиции start + msk_len - 1
        let first = start + self.msk_len as usize - 1;
        for p in first..buf.len() {
            if buf[p] & cm == key {
                let needs_confirm = self.msk_len != 1;
                if self.confirm_and_report(buf, p, needs_confirm, cb) == ScanCtl::Terminate {
                    return ExecResult::Terminated;
                }
            }
        }
        ExecResult::Completed
    }

    fn scan_double(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ExecResult {
        let cm = Self::case_mask(self.nocase);
        let k0 = self.key0 & cm;
        let k1 = self.key1 & cm;
        let ko = self.key_offset as usize;
        // scanDoubleMain: p in [start + msk_len - key_offset, len - key_offset + 1);
        // правая граница гарантирует p+1 < len (key_offset >= 2 по parse).
        let first = (start + self.msk_len as usize).saturating_sub(ko);
        let last_excl = (buf.len() + 1).saturating_sub(ko);
        for p in first..last_excl {
            if buf[p] & cm == k0 && buf[p + 1] & cm == k1 {
                if self.confirm_and_report(buf, p, true, cb) == ScanCtl::Terminate {
                    return ExecResult::Terminated;
                }
            }
        }
        ExecResult::Completed
    }

    /// Порт `final()`: подтверждение по маске + отчёт.
    fn confirm_and_report(
        &self,
        buf: &[u8],
        p: usize,
        needs_confirm: bool,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ScanCtl {
        let ko = self.key_offset as usize;
        let ml = self.msk_len as usize;
        if needs_confirm {
            debug_assert!(p + ko >= ml && p + ko <= buf.len());
            let Some(window) = (p + ko)
                .checked_sub(ml)
                .and_then(|lo| buf.get(lo..p + ko))
            else {
                return ScanCtl::Continue;
            };
            // partial_load_u64a: первые байты окна — младшие байты слова
            let mut v = 0u64;
            for (i, &b) in window.iter().enumerate() {
                v |= (b as u64) << (8 * i);
            }
            if v & self.msk != self.cmp {
                return ScanCtl::Continue;
            }
        }
        cb((p + ko - 1) as u64, self.id)
    }
}
