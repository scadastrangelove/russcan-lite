//! Фасад russcan: загрузка сериализованной БД vectorscan + `scan_block`.
//!
//! Компиляция паттернов остаётся за C++ vectorscan (оффлайн, Д1 плана).
//!
//! FDR-only срез (Ф2-lite): block-mode pure-literal скан. Путь повторяет
//! `pureLiteralBlockExec` (`runtime.c`): floating FDR-таблица → confirm →
//! `roseRunProgram_l` → внешний отчёт. Вне скоупа (NFA, anchored, streaming,
//! non-FDR floating) — явная ошибка, не молчаливый неверный результат.

use russcan_bytecode::rose::RoseEngine;
use russcan_bytecode::{DbError, SerializedDb};
use std::collections::BTreeMap;
use russcan_hwlm::fdr::FdrTable;
use russcan_hwlm::teddy::TeddyTable;
use russcan_hwlm::ScanCtl;
use russcan_rose::literal::{run_program, Dedupe, InterpError};

#[derive(Debug)]
pub enum ScanError {
    Db(DbError),
    Rose(russcan_bytecode::rose::RoseError),
    Fdr(russcan_hwlm::HwlmError),
    Interp(InterpError),
}
impl core::fmt::Display for ScanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScanError::Db(e) => write!(f, "БД: {e}"),
            ScanError::Rose(e) => write!(f, "RoseEngine: {e}"),
            ScanError::Fdr(e) => write!(f, "FDR: {e}"),
            ScanError::Interp(e) => write!(f, "интерпретатор: {e}"),
        }
    }
}
impl std::error::Error for ScanError {}
impl From<DbError> for ScanError {
    fn from(e: DbError) -> Self {
        ScanError::Db(e)
    }
}
impl From<russcan_bytecode::rose::RoseError> for ScanError {
    fn from(e: russcan_bytecode::rose::RoseError) -> Self {
        ScanError::Rose(e)
    }
}
impl From<russcan_hwlm::HwlmError> for ScanError {
    fn from(e: russcan_hwlm::HwlmError) -> Self {
        ScanError::Fdr(e)
    }
}
impl From<InterpError> for ScanError {
    fn from(e: InterpError) -> Self {
        ScanError::Interp(e)
    }
}

/// Литеральный floating-движок: plain FDR (engineID 0) или base Teddy (11–18).
enum Floating<'a> {
    Fdr(FdrTable<'a>),
    Teddy(TeddyTable<'a>),
}

/// Скомпилированная (C++ vectorscan) и провалидированная БД, готовая к скану.
pub struct Database<'a> {
    rose: RoseEngine<'a>,
    floating: Floating<'a>,
}

impl<'a> Database<'a> {
    /// Разбирает сериализованную БД и локализует floating-матчер (FDR/Teddy).
    /// Ошибка, если БД вне скоупа (не block, не pure-literal, не FDR-семейство).
    pub fn load(serialized: &'a [u8]) -> Result<Self, ScanError> {
        let db = SerializedDb::parse(serialized)?;
        let rose = RoseEngine::parse(db.bytecode())?;
        let table = rose.floating_matcher_table()?;
        // engineID (первые 4 байта): 0 = plain FDR, 11–18 = base Teddy.
        let engine_id = table
            .get(0..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(u32::MAX);
        let floating = if engine_id == 0 {
            Floating::Fdr(FdrTable::parse(table)?)
        } else {
            Floating::Teddy(TeddyTable::parse(table)?)
        };
        Ok(Database { rose, floating })
    }

    /// Block-mode скан. `on_match(id, to)` — внешний report id и end-offset
    /// (как в hs: индекс последнего байта + 1, с учётом offset_adjust).
    /// Возврат `ScanCtl::Terminate` из колбэка останавливает скан.
    pub fn scan_block<F: FnMut(u32, u64) -> ScanCtl>(
        &self,
        data: &[u8],
        on_match: &mut F,
    ) -> Result<(), ScanError> {
        let mut scan = DelayScan {
            rose: &self.rose,
            data,
            groups: self.rose.initial_groups,
            dedupe: Dedupe::default(),
            slots: BTreeMap::new(),
            delay_last_end: 0,
            scratch_delayed: Vec::new(),
            on_match,
            err: None,
        };

        match &self.floating {
            Floating::Fdr(fdr) => {
                fdr.exec_squash(data, 0, &mut |e, p| scan.on_hit(e, p));
            }
            Floating::Teddy(teddy) => {
                teddy.exec_squash(data, 0, &mut |e, p| scan.on_hit(e, p));
            }
        }
        // cleanUpDelayed: доиграть отложенные до конца буфера.
        if scan.err.is_none() {
            scan.flush(data.len() as u64);
        }

        if let Some(e) = scan.err {
            return Err(ScanError::Interp(e));
        }
        Ok(())
    }
}

/// Состояние прогона с отложенными литералами (порт delay-slot реплея,
/// `match.c` flushQueuedLiterals/playDelaySlot). Слоты — по абсолютному
/// offset реплея (проще кольца mod-32, семантически эквивалентно для block).
struct DelayScan<'a, 'd, F: FnMut(u32, u64) -> ScanCtl> {
    rose: &'d RoseEngine<'a>,
    data: &'d [u8],
    groups: u64,
    dedupe: Dedupe,
    /// offset реплея → множество delay-index (BTreeSet = порядок fatbit_iterate).
    slots: BTreeMap<u64, std::collections::BTreeSet<u32>>,
    /// delayLastEndOffset — докуда отложенные уже доиграны.
    delay_last_end: u64,
    scratch_delayed: Vec<(u8, u32)>,
    on_match: &'d mut F,
    err: Option<InterpError>,
}

impl<F: FnMut(u32, u64) -> ScanCtl> DelayScan<'_, '_, F> {
    /// Прямой матч из floating-таблицы на end_last_byte. Возвращает
    /// `(ScanCtl, squash)` — squash-байт INCLUDED_JUMP для conf-цикла.
    fn on_hit(&mut self, end_last_byte: u64, prog_off: u32) -> (ScanCtl, u8) {
        if self.err.is_some() {
            return (ScanCtl::Terminate, 0);
        }
        let real_end = end_last_byte + 1;
        // Реплей отложенных ДО прямого матча (delayed@O фаерятся раньше direct@O).
        if self.flush(real_end) == ScanCtl::Terminate {
            return (ScanCtl::Terminate, 0);
        }
        // in_confirm=true: INCLUDED_JUMP гасит бакет child и прыгает.
        self.run_prog(prog_off, real_end, true)
    }

    /// Доиграть отложенные литералы для offset в (delay_last_end, curr_end].
    fn flush(&mut self, curr_end: u64) -> ScanCtl {
        // Все ключи slots > delay_last_end (skip-check при пуше это гарантирует).
        // Берём наименьший offset ≤ curr_end; цепочные пуши при реплее могут
        // добавить новые offset ≤ curr_end — цикл их подхватит (порядок ↑).
        loop {
            let Some(&o) = self.slots.keys().next() else { break };
            if o > curr_end {
                break;
            }
            let indices = self.slots.remove(&o).unwrap();
            // Продвигаем delay_last_end ДО реплея: цепочный self-push с delay=0
            // даёт replay==o ≤ delay_last_end → skip (иначе бесконечный цикл на
            // враждебной БД; vuln-scan F-012). Легальные пуши (delay≥1,
            // replay>o) по-прежнему вставляются.
            self.delay_last_end = self.delay_last_end.max(o);
            for idx in indices {
                let prog = match self.rose.delay_program(idx) {
                    Ok(p) => p,
                    Err(e) => {
                        self.err = Some(e.into());
                        return ScanCtl::Terminate;
                    }
                };
                // Delayed-реплей: fdr_conf нет → in_confirm=false (INCLUDED_JUMP
                // не прыгает). squash здесь смысла не имеет.
                if self.run_prog(prog, o, false).0 == ScanCtl::Terminate {
                    return ScanCtl::Terminate;
                }
            }
        }
        self.delay_last_end = curr_end.max(self.delay_last_end);
        ScanCtl::Continue
    }

    /// Прогон программы на hs-offset `end_hs`; PUSH_DELAYED из неё → в slots.
    /// Возвращает `(ScanCtl, squash)` (squash непуст только при in_confirm).
    fn run_prog(&mut self, prog_off: u32, end_hs: u64, in_confirm: bool) -> (ScanCtl, u8) {
        let Self {
            rose,
            data,
            groups,
            dedupe,
            scratch_delayed,
            on_match,
            ..
        } = self;
        scratch_delayed.clear();
        let mut squash = 0u8;
        let ctl = match run_program(
            rose,
            prog_off,
            end_hs - 1, // run_program сделает +1 → end_hs
            data,
            groups, // &mut: SET_GROUPS/SQUASH_GROUPS сохраняются между матчами
            dedupe,
            on_match,
            scratch_delayed,
            in_confirm,
            &mut squash,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.err = Some(e);
                return (ScanCtl::Terminate, 0);
            }
        };
        // rosePushDelayedMatch: replay_offset = end_hs + delay,
        // skip если replay_offset ≤ delay_last_end.
        for &(delay, index) in self.scratch_delayed.iter() {
            let replay = end_hs + delay as u64;
            if replay <= self.delay_last_end {
                continue;
            }
            self.slots.entry(replay).or_default().insert(index);
        }
        (ctl, squash)
    }
}
