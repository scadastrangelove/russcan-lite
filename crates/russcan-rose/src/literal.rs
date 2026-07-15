//! Интерпретатор pure-literal rose-программ (`roseRunProgram_l`,
//! `program_runtime.c` @ a1c107e). Урезанный набор: 24 опкода литерального
//! пути, из которых реально порождаются нашими наборами ~8 (перепись Д3).
//! На неизвестный/вне-скоупа опкод — `UnsupportedOpcode` (fail-fast, не паника):
//! вход недоверенный, а «молчаливый пропуск» ломал бы дифф с оракулом.
//!
//! Block mode: buf_offset=0, история пуста — проверки байтов/литералов
//! соответственно упрощены (см. `roseCheckByte`/`roseCheckMediumLiteral`).

use russcan_bytecode::rose::{RoseEngine, RoseError};
use russcan_hwlm::ScanCtl;
use russcan_nfa::{dispatch::Nfa, NfaError};
use std::collections::HashSet;

// Опкоды (значения enum RoseInstructionCode, layout_probe @ 5.4.12).
#[allow(dead_code)]
mod op {
    pub const END: u8 = 0;
    pub const CHECK_LIT_EARLY: u8 = 2;
    pub const CHECK_GROUPS: u8 = 3;
    pub const CHECK_BOUNDS: u8 = 5;
    pub const CHECK_NOT_HANDLED: u8 = 6;
    pub const CHECK_SINGLE_LOOKAROUND: u8 = 7;
    pub const CHECK_LOOKAROUND: u8 = 8;
    pub const CHECK_MASK: u8 = 9;
    pub const CHECK_MASK_32: u8 = 10;
    pub const CHECK_BYTE: u8 = 11;
    pub const CHECK_SHUFTI_16X8: u8 = 12;
    pub const CHECK_SHUFTI_32X8: u8 = 13;
    pub const CHECK_SHUFTI_16X16: u8 = 14;
    pub const CHECK_SHUFTI_32X16: u8 = 15;
    pub const CHECK_INFIX: u8 = 16;
    pub const CHECK_PREFIX: u8 = 17;
    pub const PUSH_DELAYED: u8 = 18;
    pub const CATCH_UP: u8 = 20;
    pub const CATCH_UP_MPV: u8 = 21;
    pub const TRIGGER_INFIX: u8 = 26;
    pub const TRIGGER_SUFFIX: u8 = 27;
    pub const REPORT: u8 = 33;
    pub const DEDUPE_AND_REPORT: u8 = 37;
    pub const FINAL_REPORT: u8 = 38;
    pub const SET_STATE: u8 = 41;
    pub const SET_GROUPS: u8 = 42;
    pub const SQUASH_GROUPS: u8 = 43;
    pub const CHECK_STATE: u8 = 44;
    pub const CHECK_MED_LIT: u8 = 53;
    pub const CHECK_MED_LIT_NOCASE: u8 = 54;
    pub const INCLUDED_JUMP: u8 = 61;
}

const MIN_ALIGN: usize = 8; // ROSE_INSTR_MIN_ALIGN

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpError {
    Rose(RoseError),
    /// Опкод вне FDR-only скоупа (напр. TRIGGER_SUFFIX, CATCH_UP — требуют NFA).
    UnsupportedOpcode(u8),
    /// pc вышел за границы программы/байткода.
    ProgramOverrun,
    /// Ошибка leftfix-движка при CHECK_PREFIX (разбор/тип NFA).
    Nfa(NfaError),
}
impl From<NfaError> for InterpError {
    fn from(e: NfaError) -> Self {
        InterpError::Nfa(e)
    }
}
impl From<RoseError> for InterpError {
    fn from(e: RoseError) -> Self {
        InterpError::Rose(e)
    }
}
impl core::fmt::Display for InterpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InterpError::Rose(e) => write!(f, "{e}"),
            InterpError::UnsupportedOpcode(c) => {
                write!(f, "опкод {c} вне FDR-only скоупа")
            }
            InterpError::ProgramOverrun => write!(f, "pc за пределами программы"),
            InterpError::Nfa(e) => write!(f, "leftfix: {e}"),
        }
    }
}
impl std::error::Error for InterpError {}

/// FxHash-подобный хешер (rotate-xor-multiply) вместо дефолтного SipHash:
/// dedup — hot-path (десятки млн вставок/скан на матч-плотном трафике), а
/// DoS-стойкость SipHash тут не нужна (ключи — свои dkey/offset). Профиль:
/// SipHash доминировал в run_prog.
#[derive(Default)]
struct FxHasher(u64);
const FX_SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
impl core::hash::Hasher for FxHasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(5) ^ b as u64).wrapping_mul(FX_SEED);
        }
    }
    #[inline(always)]
    fn write_u32(&mut self, i: u32) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(FX_SEED);
    }
    #[inline(always)]
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(FX_SEED);
    }
}
#[derive(Default, Clone)]
struct FxBuild;
impl core::hash::BuildHasher for FxBuild {
    type Hasher = FxHasher;
    #[inline(always)]
    fn build_hasher(&self) -> FxHasher {
        FxHasher(0)
    }
}

/// Per-scan scratch интерпретатора: дедуп внешних отчётов по (dkey, offset)
/// (порт `scratch->deduper`), `handled_roles` (CHECK_NOT_HANDLED — test-and-set
/// ключа роли), и накопитель suffix-триггеров (TRIGGER_SUFFIX): движки-суффиксы
/// запускаются лениво в конце скана (порт `roseCatchUpTo(length)`), поэтому
/// триггеры `(queue, event, loc)` копятся и доигрываются вызывающим.
#[derive(Default)]
pub struct Dedupe {
    seen: HashSet<(u32, u64), FxBuild>,
    handled: HashSet<u32, FxBuild>,
    suffix: Vec<(u32, u32, u64)>,
    /// TRIGGER_INFIX-триггеры (queue, trigger-loc): CHECK_INFIX гоняет infix-NFA
    /// от каждого триггера T≤loc и проверяет accept (объединение по TOP-ам).
    infix: Vec<(u32, u64)>,
    /// Role-state мультибит (порт `getRoleState`): SET_STATE ставит индекс,
    /// CHECK_STATE проверяет. Сохраняется между литеральными матчами скана.
    role_state: HashSet<u32, FxBuild>,
}
impl Dedupe {
    pub fn clear(&mut self) {
        self.seen.clear();
        self.handled.clear();
        self.suffix.clear();
        self.infix.clear();
        self.role_state.clear();
    }
    /// SET_STATE: включить бит роли `index`.
    fn set_role_state(&mut self, index: u32) {
        self.role_state.insert(index);
    }
    /// CHECK_STATE: бит роли `index` включён?
    fn role_state_set(&self, index: u32) -> bool {
        self.role_state.contains(&index)
    }
    /// true, если пара новая (нужно репортить).
    fn fresh(&mut self, dkey: u32, off: u64) -> bool {
        self.seen.insert((dkey, off))
    }
    /// true, если ключ роли ещё НЕ встречался (порт `!fatbit_set`): продолжаем.
    /// false — уже видели (CHECK_NOT_HANDLED → fail_jump).
    fn not_handled(&mut self, key: u32) -> bool {
        self.handled.insert(key)
    }
    /// Записать TRIGGER_SUFFIX-триггер (queue, event, trigger-loc).
    fn push_suffix(&mut self, queue: u32, event: u32, loc: u64) {
        self.suffix.push((queue, event, loc));
    }
    /// Забрать накопленные suffix-триггеры (для ленивого прогона в конце скана).
    pub fn take_suffix(&mut self) -> Vec<(u32, u32, u64)> {
        core::mem::take(&mut self.suffix)
    }
    /// Записать TRIGGER_INFIX-триггер. `cancel` — доминирующий top: сбрасывает
    /// прежние триггеры этой очереди (порт reinit очереди в roseTriggerInfix).
    fn push_infix(&mut self, queue: u32, loc: u64, cancel: bool) {
        if cancel {
            self.infix.retain(|&(q, _)| q != queue);
        }
        self.infix.push((queue, loc));
    }
    /// Trigger-локи infix-очереди `queue`, накопленные к текущему моменту скана.
    fn infix_locs(&self, queue: u32) -> Vec<u64> {
        self.infix
            .iter()
            .filter(|&&(q, _)| q == queue)
            .map(|&(_, l)| l)
            .collect()
    }
}

// Fallible LE-чтения операндов: программа недоверенная (может быть обрезана в
// конце байткода), поэтому OOB операнда → ProgramOverrun (fail-fast), а не
// index/unwrap-паника. Закрывает vuln-scan F-003. Только опкод-байт раньше был
// bounds-checked; операнды — нет.
fn le32(b: &[u8], o: usize) -> Result<u32, InterpError> {
    let s = b.get(o..o + 4).ok_or(InterpError::ProgramOverrun)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}
fn le64(b: &[u8], o: usize) -> Result<u64, InterpError> {
    let s = b.get(o..o + 8).ok_or(InterpError::ProgramOverrun)?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

/// Прогон программы литерала по оффсету `prog_off` для матча, закончившегося
/// на `end` (индекс последнего байта + 1 в терминах hs → здесь `end` уже
/// «to»-оффсет floating-таблицы: индекс последнего байта). `groups` —
/// `tctxt.groups`: изменяемое состояние скана (SET_GROUPS/SQUASH_GROUPS его
/// правят, CHECK_GROUPS читает), сохраняется между литеральными матчами.
/// `report(onmatch, to)` фаерит внешний отчёт.
///
/// Возвращает `ScanCtl` (продолжать/терминировать общий скан).
///
/// `#[inline]`: единственный вызыватель — `DelayScan::run_prog` (десятки млн
/// вызовов/скан на матч-плотном трафике); без инлайна ~30% времени уходило на
/// маршалинг 10 аргументов (4 через стек) + фрейм (профиль run_prog).
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn run_program(
    rose: &RoseEngine,
    prog_off: u32,
    end_last_byte: u64,
    buf: &[u8],
    groups: &mut u64,
    dedupe: &mut Dedupe,
    report: &mut impl FnMut(u32, u64) -> ScanCtl,
    // Сбор PUSH_DELAYED: (delay-байты, delay-index). Оффсет реплея вычисляет
    // вызывающий (фасад) по `end`.
    delayed: &mut Vec<(u8, u32)>,
    // Контекст confirm (прямой матч из FDR/Teddy): в нём INCLUDED_JUMP
    // squash'ит бакет child (см. `squash_out`). В delayed-реплее fdr_conf нет
    // → INCLUDED_JUMP не прыгает (fall-through), как в C.
    in_confirm: bool,
    // Аккумулятор squash-байтов INCLUDED_JUMP (OR); применяет caller к conf.
    squash_out: &mut u8,
) -> Result<ScanCtl, InterpError> {
    // hs репортит «end offset» = индекс_последнего_байта + 1.
    let end = end_last_byte + 1;
    let mut prog = rose.by_offset(prog_off as usize)?;
    let mut pc = 0usize;

    // Бюджет инструкций: валидная программа завершается за O(размер байткода)
    // шагов (каждая инструкция ≥ MIN_ALIGN байт; INCLUDED_JUMP-дерево тоже
    // ограничено). Превышение = цикл (fail_jump=0 или цикличный INCLUDED_JUMP
    // child_offset на враждебной БД) → fail-fast, а не вечный цикл.
    // Закрывает vuln-scan F-007/F-008. Off-scan-hot-path на пустом трафике.
    let max_steps = rose.bytecode().len() + MIN_ALIGN;
    let mut steps = 0usize;

    // Порт `work_done`: SQUASH_GROUPS гасит группу только если в этой программе
    // была «работа» (report/trigger/set_state).
    let mut work_done = false;

    loop {
        steps += 1;
        if steps > max_steps {
            return Err(InterpError::ProgramOverrun);
        }
        let code = *prog.get(pc).ok_or(InterpError::ProgramOverrun)?;
        // размер текущей инструкции (для продвижения) — задаём в каждой ветке.
        match code {
            op::END => return Ok(ScanCtl::Continue),

            op::CHECK_GROUPS => {
                let g = le64(prog, pc + 8)?;
                if g & *groups == 0 {
                    return Ok(ScanCtl::Continue); // программа останавливается
                }
                pc += roundup(16);
            }

            op::CHECK_BYTE => {
                let and_mask = *prog.get(pc + 1).ok_or(InterpError::ProgramOverrun)?;
                let cmp_mask = *prog.get(pc + 2).ok_or(InterpError::ProgramOverrun)?;
                let negation = *prog.get(pc + 3).ok_or(InterpError::ProgramOverrun)?;
                let offset = le32(prog, pc + 4)? as i32;
                let fail_jump = le32(prog, pc + 8)? as usize;
                if check_byte(buf, and_mask, cmp_mask, negation, offset, end) {
                    pc += roundup(12);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_LIT_EARLY => {
                // struct: code@0, min_offset u32@4, fail_jump u32@8; sizeof 12.
                // roseCheckLitEarly: end < min_offset → провал (матч слишком рано).
                let min_offset = le32(prog, pc + 4)? as u64;
                let fail_jump = le32(prog, pc + 8)? as usize;
                if end < min_offset {
                    pc += fail_jump;
                } else {
                    pc += roundup(12);
                }
            }

            op::CHECK_SHUFTI_16X8 => {
                // struct: code@0, nib_mask[32]@1, bucket_select_mask[16]@33,
                // neg_mask u32@52, offset s32@56, fail_jump u32@60; sizeof 64.
                // roseCheckShufti16x8 (lookaround-фильтр перед leftfix).
                let nib_mask = prog.get(pc + 1..pc + 33).ok_or(InterpError::ProgramOverrun)?;
                let bucket = prog.get(pc + 33..pc + 49).ok_or(InterpError::ProgramOverrun)?;
                let neg_mask = le32(prog, pc + 52)?;
                let check_offset = le32(prog, pc + 56)? as i32;
                let fail_jump = le32(prog, pc + 60)? as usize;
                if check_shufti_16x8(buf, nib_mask, bucket, neg_mask, check_offset, end) {
                    pc += roundup(64);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_MASK => {
                // struct: code@0, and_mask u64@8, cmp_mask u64@16,
                // neg_mask u64@24, offset s32@32, fail_jump u32@36; sizeof 40.
                // roseCheckMask: 8-байтная and/cmp/neg-проверка (block mode).
                let and_mask = le64(prog, pc + 8)?;
                let cmp_mask = le64(prog, pc + 16)?;
                let neg_mask = le64(prog, pc + 24)?;
                let check_offset = le32(prog, pc + 32)? as i32;
                let fail_jump = le32(prog, pc + 36)? as usize;
                if check_mask(buf, and_mask, cmp_mask, neg_mask, check_offset, end) {
                    pc += roundup(40);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_BOUNDS => {
                // struct: code@0, min_bound u64@8, max_bound u64@16,
                // fail_jump u32@24; sizeof 32. roseCheckBounds.
                let min_bound = le64(prog, pc + 8)?;
                let max_bound = le64(prog, pc + 16)?;
                let fail_jump = le32(prog, pc + 24)? as usize;
                if end >= min_bound && end <= max_bound {
                    pc += roundup(32);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_NOT_HANDLED => {
                // struct: code@0, key u32@4, fail_jump u32@8; sizeof 12.
                // roseCheckNotHandled: ключ роли уже виден в скане → fail_jump.
                let key = le32(prog, pc + 4)?;
                let fail_jump = le32(prog, pc + 8)? as usize;
                if dedupe.not_handled(key) {
                    pc += roundup(12);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_SINGLE_LOOKAROUND => {
                // struct: code@0, offset s8@1, reach_index u32@4,
                // fail_jump u32@8; sizeof 12. roseCheckSingleLookaround.
                let check_offset = *prog.get(pc + 1).ok_or(InterpError::ProgramOverrun)? as i8;
                let reach_index = le32(prog, pc + 4)? as usize;
                let fail_jump = le32(prog, pc + 8)? as usize;
                let reach = rose.by_offset(reach_index)?;
                if check_single_lookaround(buf, reach, check_offset, end) {
                    pc += roundup(12);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_LOOKAROUND => {
                // struct: code@0, look_index u32@4, reach_index u32@8,
                // count u32@12, fail_jump u32@16; sizeof 20. roseCheckLookaround.
                let look_index = le32(prog, pc + 4)? as usize;
                let reach_index = le32(prog, pc + 8)? as usize;
                let count = le32(prog, pc + 12)? as usize;
                let fail_jump = le32(prog, pc + 16)? as usize;
                let look = rose.by_offset(look_index)?;
                let reach = rose.by_offset(reach_index)?;
                if check_lookaround(buf, look, reach, count, end)? {
                    pc += roundup(20);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_MASK_32 => {
                // struct: code@0, and_mask[32]@1, cmp_mask[32]@33,
                // neg_mask u32@68, offset s32@72, fail_jump u32@76; sizeof 80.
                let and_mask = prog.get(pc + 1..pc + 33).ok_or(InterpError::ProgramOverrun)?;
                let cmp_mask = prog.get(pc + 33..pc + 65).ok_or(InterpError::ProgramOverrun)?;
                let neg_mask = le32(prog, pc + 68)?;
                let check_offset = le32(prog, pc + 72)? as i32;
                let fail_jump = le32(prog, pc + 76)? as usize;
                if check_mask32(buf, and_mask, cmp_mask, neg_mask, check_offset, end) {
                    pc += roundup(80);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_SHUFTI_32X8 => {
                // struct: code@0, hi_mask[16]@1, lo_mask[16]@17,
                // bucket_select_mask[32]@33, neg_mask u32@68, offset s32@72,
                // fail_jump u32@76; sizeof 80. roseCheckShufti32x8.
                let hi = prog.get(pc + 1..pc + 17).ok_or(InterpError::ProgramOverrun)?;
                let lo = prog.get(pc + 17..pc + 33).ok_or(InterpError::ProgramOverrun)?;
                let bucket = prog.get(pc + 33..pc + 65).ok_or(InterpError::ProgramOverrun)?;
                let neg_mask = le32(prog, pc + 68)?;
                let check_offset = le32(prog, pc + 72)? as i32;
                let fail_jump = le32(prog, pc + 76)? as usize;
                if check_shufti_32x8(buf, hi, lo, bucket, neg_mask, check_offset, end) {
                    pc += roundup(80);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_SHUFTI_16X16 => {
                // struct: code@0, hi_mask[32]@1, lo_mask[32]@33,
                // bucket_select_mask[32]@65, neg_mask u32@100, offset s32@104,
                // fail_jump u32@108; sizeof 112. roseCheckShufti16x16.
                let hi = prog.get(pc + 1..pc + 33).ok_or(InterpError::ProgramOverrun)?;
                let lo = prog.get(pc + 33..pc + 65).ok_or(InterpError::ProgramOverrun)?;
                let bucket = prog.get(pc + 65..pc + 97).ok_or(InterpError::ProgramOverrun)?;
                let neg_mask = le32(prog, pc + 100)?;
                let check_offset = le32(prog, pc + 104)? as i32;
                let fail_jump = le32(prog, pc + 108)? as usize;
                if check_shufti_16x16(buf, hi, lo, bucket, neg_mask, check_offset, end) {
                    pc += roundup(112);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_SHUFTI_32X16 => {
                // struct: code@0, hi_mask[32]@1, lo_mask[32]@33,
                // bucket_select_mask_hi[32]@65, bucket_select_mask_lo[32]@97,
                // neg_mask u32@132, offset s32@136, fail_jump u32@140; sizeof 144.
                let hi = prog.get(pc + 1..pc + 33).ok_or(InterpError::ProgramOverrun)?;
                let lo = prog.get(pc + 33..pc + 65).ok_or(InterpError::ProgramOverrun)?;
                let bsm_hi = prog.get(pc + 65..pc + 97).ok_or(InterpError::ProgramOverrun)?;
                let bsm_lo = prog.get(pc + 97..pc + 129).ok_or(InterpError::ProgramOverrun)?;
                let neg_mask = le32(prog, pc + 132)?;
                let check_offset = le32(prog, pc + 136)? as i32;
                let fail_jump = le32(prog, pc + 140)? as usize;
                if check_shufti_32x16(buf, hi, lo, bsm_hi, bsm_lo, neg_mask, check_offset, end) {
                    pc += roundup(144);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_INFIX => {
                // struct: code@0, queue u32@4, lag u32@8, report u32@12,
                // fail_jump u32@16; sizeof 20. Порт roseTestInfix (block mode).
                // В отличие от prefix, infix активируется TRIGGER_INFIX: гоняем
                // NFA от каждого триггера T≤loc по buf[T..loc]; accept у любого
                // (объединение по TOP-ам) → проверка пройдена. loc = end - lag.
                let queue = le32(prog, pc + 4)?;
                let lag = le32(prog, pc + 8)? as u64;
                let report = le32(prog, pc + 12)?;
                let fail_jump = le32(prog, pc + 16)? as usize;
                let mut accepted = false;
                if end >= lag {
                    let loc = (end - lag) as usize;
                    if loc <= buf.len() {
                        let locs = dedupe.infix_locs(queue);
                        if !locs.is_empty() {
                            let nfa = Nfa::from_bytes(rose.nfa_by_queue(queue)?)?;
                            for t in locs {
                                let t = t as usize;
                                if t <= loc && nfa.in_accept_state(&buf[t..loc], report)? {
                                    accepted = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if accepted {
                    pc += roundup(20);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_PREFIX => {
                // struct ROSE_STRUCT_CHECK_PREFIX: code@0, queue u32@4,
                // lag u32@8, report u32@12, fail_jump u32@16; sizeof 20.
                // Порт roseTestPrefix (block mode, buf_offset=0). Стриминговые
                // оптимизации (active-left bitmap, кэш очереди, miracles)
                // семантику не меняют — прогоняем prefix-NFA по buf[0..loc] и
                // спрашиваем nfaInAcceptState(report). loc = end - lag.
                let queue = le32(prog, pc + 4)?;
                let lag = le32(prog, pc + 8)? as u64;
                let report = le32(prog, pc + 12)?;
                let fail_jump = le32(prog, pc + 16)? as usize;
                // roseTestLeftfix: end < leftfixLag → провал (lag = длина литерала).
                let accepted = if end < lag {
                    false
                } else {
                    let loc = (end - lag) as usize;
                    let hay = buf.get(..loc).ok_or(InterpError::ProgramOverrun)?;
                    let nfa = Nfa::from_bytes(rose.nfa_by_queue(queue)?)?;
                    nfa.in_accept_state(hay, report)?
                };
                if accepted {
                    pc += roundup(20);
                } else {
                    pc += fail_jump;
                }
            }

            op::CHECK_MED_LIT | op::CHECK_MED_LIT_NOCASE => {
                let nocase = code == op::CHECK_MED_LIT_NOCASE;
                let lit_offset = le32(prog, pc + 4)? as usize;
                let lit_length = le32(prog, pc + 8)? as usize;
                let fail_jump = le32(prog, pc + 12)? as usize;
                let lit = rose.by_offset(lit_offset)?;
                if check_med_lit(buf, lit, lit_length, end, nocase) {
                    pc += roundup(16);
                } else {
                    pc += fail_jump;
                }
            }

            op::REPORT => {
                let onmatch = le32(prog, pc + 4)?;
                let off_adj = le32(prog, pc + 8)? as i32;
                let to = (end as i64 + off_adj as i64) as u64;
                work_done = true;
                if report(onmatch, to) == ScanCtl::Terminate {
                    return Ok(ScanCtl::Terminate);
                }
                pc += roundup(12);
            }

            op::FINAL_REPORT => {
                let onmatch = le32(prog, pc + 4)?;
                let off_adj = le32(prog, pc + 8)? as i32;
                let to = (end as i64 + off_adj as i64) as u64;
                let ctl = report(onmatch, to);
                // one-shot: всегда завершает программу
                return Ok(ctl);
            }

            op::DEDUPE_AND_REPORT => {
                let dkey = le32(prog, pc + 4)?;
                let onmatch = le32(prog, pc + 8)?;
                let off_adj = le32(prog, pc + 12)? as i32;
                let fail_jump = le32(prog, pc + 16)? as usize;
                let to = (end as i64 + off_adj as i64) as u64;
                work_done = true;
                if dedupe.fresh(dkey, to) {
                    if report(onmatch, to) == ScanCtl::Terminate {
                        return Ok(ScanCtl::Terminate);
                    }
                    pc += roundup(20);
                } else {
                    pc += fail_jump; // DEDUPE_SKIP
                }
            }

            op::INCLUDED_JUMP => {
                // struct: code@0, squash u8@1, child_offset u32@4.
                // C: только если fdr_conf установлен (мы в confirm) — squash
                // бакета child + прыжок; иначе fall-through.
                if in_confirm {
                    *squash_out |= *prog.get(pc + 1).ok_or(InterpError::ProgramOverrun)?;
                    let child_offset = le32(prog, pc + 4)? as usize;
                    prog = rose.by_offset(child_offset)?;
                    pc = 0;
                } else {
                    pc += roundup(8);
                }
            }

            op::PUSH_DELAYED => {
                // struct: code@0, delay u8@1, index u32@4. Реплей делает фасад.
                let delay = *prog.get(pc + 1).ok_or(InterpError::ProgramOverrun)?;
                let index = le32(prog, pc + 4)?;
                delayed.push((delay, index));
                pc += roundup(8);
            }

            op::TRIGGER_SUFFIX => {
                // struct: code@0, queue u32@4, event u32@8; sizeof 12.
                // roseTriggerSuffix: активируем суффикс (TOP на loc=end). Сам
                // движок гоняется лениво в конце скана (roseCatchUpTo(length)) —
                // накапливаем триггер, вызывающий доигрывает.
                let queue = le32(prog, pc + 4)?;
                let event = le32(prog, pc + 8)?;
                dedupe.push_suffix(queue, event, end);
                work_done = true;
                pc += roundup(12);
            }

            op::TRIGGER_INFIX => {
                // struct: code@0, queue u32@4, event u32@8, cancel u8@12;
                // sizeof 16. roseTriggerInfix: TOP на loc=end; cancel — сброс
                // прежних триггеров (доминирующий top). Проверяет CHECK_INFIX.
                let queue = le32(prog, pc + 4)?;
                let _event = le32(prog, pc + 8)?;
                let cancel = *prog.get(pc + 12).ok_or(InterpError::ProgramOverrun)? != 0;
                dedupe.push_infix(queue, end, cancel);
                work_done = true;
                pc += roundup(16);
            }

            op::SET_STATE => {
                // struct: code@0, index u32@4; sizeof 8. Включить бит роли.
                let index = le32(prog, pc + 4)?;
                dedupe.set_role_state(index);
                work_done = true;
                pc += roundup(8);
            }

            op::CHECK_STATE => {
                // struct: code@0, index u32@4, fail_jump u32@8; sizeof 12.
                // Бит роли `index` не включён → провал.
                let index = le32(prog, pc + 4)?;
                let fail_jump = le32(prog, pc + 8)? as usize;
                if dedupe.role_state_set(index) {
                    pc += roundup(12);
                } else {
                    pc += fail_jump;
                }
            }

            op::SET_GROUPS => {
                // struct: code@0, groups u64@8; sizeof 16. groups |= mask.
                let mask = le64(prog, pc + 8)?;
                *groups |= mask;
                pc += roundup(16);
            }

            op::SQUASH_GROUPS => {
                // struct: code@0, groups u64@8; sizeof 16. Если была работа —
                // groups &= mask (гасит одну группу после матча роли).
                let mask = le64(prog, pc + 8)?;
                if work_done {
                    *groups &= mask;
                }
                pc += roundup(16);
            }

            op::CATCH_UP | op::CATCH_UP_MPV => {
                // struct: только code; sizeof 1. Гарантирует, что более ранние
                // NFA-матчи вышли до текущего. В block mode все суффиксы
                // доигрываются в конце — набор матчей не меняется, поэтому no-op
                // (сравниваем отсортированные множества).
                pc += roundup(1);
            }

            // Вне скоупа: infix-триггеры/logical/SOM и пр. Fail-fast
            // (безопасно — недоверенный вход, молчаливый пропуск ломал бы дифф).
            other => return Err(InterpError::UnsupportedOpcode(other)),
        }
    }
}

fn roundup(n: usize) -> usize {
    (n + MIN_ALIGN - 1) & !(MIN_ALIGN - 1)
}

/// Порт `roseCheckByte` (block mode: buf_offset=0, hlen=0).
fn check_byte(buf: &[u8], and_mask: u8, cmp_mask: u8, negation: u8, off: i32, end: u64) -> bool {
    if off < 0 && (0i64 - off as i64) as u64 > end {
        return false;
    }
    let offset = end as i64 + off as i64;
    let c = if offset >= 0 {
        if offset >= buf.len() as i64 {
            return true; // «в будущем» — пропускаем
        }
        buf[offset as usize]
    } else {
        return true; // до истории (её нет) — пропускаем
    };
    (((and_mask & c) != cmp_mask) ^ (negation != 0)) == false
}

/// Порт `getData128`/`getBufferDataComplex` для block mode (buf_offset=0,
/// история пуста): 16 байт с `off` (≥0 — гарантирует early-fail в вызывающем),
/// плюс `valid`-маска (бит i = байт i в пределах буфера). Хвост за концом
/// буфера — нули с погашенными valid-битами; окно целиком в будущем — valid=0.
fn get_data128(buf: &[u8], off: i64) -> ([u8; 16], u16) {
    let len = buf.len() as i64;
    let mut data = [0u8; 16];
    if off < 0 || off >= len {
        return (data, 0); // до истории (её нет) / целиком в будущем
    }
    let o = off as usize;
    if off + 16 <= len {
        data.copy_from_slice(&buf[o..o + 16]);
        return (data, 0xffff);
    }
    // частичный хвост: off < len < off+16.
    let c_len = (len - off) as usize; // 1..=15
    data[..c_len].copy_from_slice(&buf[o..len as usize]);
    let c_shift = 16 - c_len as u32;
    (data, (0xffffu16 << c_shift) >> c_shift)
}

/// Порт `validateShuftiMask16x8` (скалярно, бит-в-бит): для каждой valid-позиции
/// `t = nib_hi[hi_nibble] & nib_lo[lo_nibble]`; байт «не в бакете», если
/// `t & bucket_select == 0`. С учётом `neg_mask` все valid-позиции должны
/// «совпасть» (итог 0). `nib_mask` — 32 байта: [0..16] по младшему нибблу,
/// [16..32] по старшему.
#[doc(hidden)]
pub fn validate_shufti_16x8(
    data: &[u8; 16],
    nib_mask: &[u8],
    bucket_select: &[u8],
    neg_mask: u32,
    valid: u16,
) -> bool {
    let mut nres: u16 = 0;
    for i in 0..16 {
        let lo = (data[i] & 0x0f) as usize;
        let hi = ((data[i] >> 4) & 0x0f) as usize;
        let t = nib_mask[16 + hi] & nib_mask[lo];
        if t & bucket_select[i] == 0 {
            nres |= 1 << i;
        }
    }
    ((nres ^ neg_mask as u16) & valid) == 0
}

/// Порт `roseCheckShufti16x8` (block mode). true = фильтр пройден (продолжаем).
fn check_shufti_16x8(
    buf: &[u8],
    nib_mask: &[u8],
    bucket_select: &[u8],
    neg_mask: u32,
    check_offset: i32,
    end: u64,
) -> bool {
    // «слишком рано»: позиция окна до старта потока → провал.
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false;
    }
    let off = end as i64 + check_offset as i64;
    let (data, valid) = get_data128(buf, off);
    if valid == 0 {
        return true; // валидных данных нет → фильтр пройден
    }
    validate_shufti_16x8(&data, nib_mask, bucket_select, neg_mask, valid)
}

/// Порт `getData256`/`getBufferDataComplex` (32 байта, block mode, off≥0).
fn get_data256(buf: &[u8], off: i64) -> ([u8; 32], u32) {
    let len = buf.len() as i64;
    let mut data = [0u8; 32];
    if off < 0 || off >= len {
        return (data, 0);
    }
    let o = off as usize;
    if off + 32 <= len {
        data.copy_from_slice(&buf[o..o + 32]);
        return (data, 0xffff_ffff);
    }
    let c_len = (len - off) as usize; // 1..=31
    data[..c_len].copy_from_slice(&buf[o..len as usize]);
    let c_shift = 32 - c_len as u32;
    (data, (0xffff_ffffu32 << c_shift) >> c_shift)
}

/// `reachHasBit`: бит `c` в 256-битном (32-байтном) векторе достижимости.
/// Тотальна (обрезанный вектор → false), без паники на недоверенном байткоде.
fn reach_has_bit(reach: &[u8], c: u8) -> bool {
    reach
        .get((c >> 3) as usize)
        .is_some_and(|&b| b & (1 << (c & 7)) != 0)
}

/// Порт `roseCheckSingleLookaround` (block mode): байт на `end+offset`
/// принадлежит классу `reach`? Вне буфера (до старта / в будущем) → пройдено.
#[doc(hidden)]
pub fn check_single_lookaround(buf: &[u8], reach: &[u8], check_offset: i8, end: u64) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false; // слишком рано
    }
    let off = end as i64 + check_offset as i64;
    if off >= 0 && (off as usize) < buf.len() {
        reach_has_bit(reach, buf[off as usize])
    } else {
        true // вне буфера — проверять нечего
    }
}

/// Порт `roseCheckLookaround` (block mode): список из `count` записей
/// `(look[k]: s8 offset, reach[k]: 32-байтный класс)`, упорядочен по возрастанию
/// offset. Каждый байт в буфере должен принадлежать своему классу.
#[doc(hidden)]
pub fn check_lookaround(
    buf: &[u8],
    look: &[u8],
    reach: &[u8],
    count: usize,
    end: u64,
) -> Result<bool, InterpError> {
    if count == 0 {
        return Ok(true);
    }
    let looks = look.get(..count).ok_or(InterpError::ProgramOverrun)?;
    let reaches = reach
        .get(..count * 32)
        .ok_or(InterpError::ProgramOverrun)?;
    // early-fail по первой (наименьшей) записи.
    let first = looks[0] as i8;
    if first < 0 && (-(first as i64)) as u64 > end {
        return Ok(false);
    }
    for k in 0..count {
        let rel = looks[k] as i8 as i64;
        let off = end as i64 + rel;
        if off < 0 {
            continue; // до старта, истории нет → запись пропускается
        }
        if off >= buf.len() as i64 {
            break; // остальные — в будущем, проверять нечего
        }
        if !reach_has_bit(&reaches[k * 32..k * 32 + 32], buf[off as usize]) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Порт `validateShuftiMask32x8`: 32 байта, 8 бакетов; `hi`/`lo` — 16-байтные
/// таблицы по старшему/младшему нибблу.
#[doc(hidden)]
pub fn validate_shufti_32x8(
    data: &[u8; 32],
    hi: &[u8],
    lo: &[u8],
    bucket: &[u8],
    neg: u32,
    valid: u32,
) -> bool {
    let mut nres: u32 = 0;
    for i in 0..32 {
        let l = (data[i] & 0x0f) as usize;
        let h = ((data[i] >> 4) & 0x0f) as usize;
        let t = hi[h] & lo[l];
        if t & bucket[i] == 0 {
            nres |= 1 << i;
        }
    }
    ((nres ^ neg) & valid) == 0
}

/// Порт `validateShuftiMask16x16`: 16 байт, 16 бакетов; `hi`/`lo` — 32-байтные
/// (две 16-таблицы: low-lane [0..16] бакеты через `bucket[i]`, high-lane
/// [16..32] через `bucket[16+i]`). Байт совпал, если попал в бакет любой lane.
#[doc(hidden)]
pub fn validate_shufti_16x16(
    data: &[u8; 16],
    hi: &[u8],
    lo: &[u8],
    bucket: &[u8],
    neg: u32,
    valid: u16,
) -> bool {
    let mut nres: u16 = 0;
    for i in 0..16 {
        let l = (data[i] & 0x0f) as usize;
        let h = ((data[i] >> 4) & 0x0f) as usize;
        let t_lo = hi[h] & lo[l];
        let t_hi = hi[16 + h] & lo[16 + l];
        let m_lo = (t_lo & bucket[i]) != 0;
        let m_hi = (t_hi & bucket[16 + i]) != 0;
        if !(m_lo || m_hi) {
            nres |= 1 << i;
        }
    }
    ((nres ^ neg as u16) & valid) == 0
}

/// Порт `validateShuftiMask32x16`: 32 байта, 16 бакетов; `hi`/`lo` — 32-байтные
/// (две 16-таблицы, `_1`=[0..16], `_2`=[16..32]); `bsm_lo`/`bsm_hi` — бакет-
/// маски для низких/высоких 8 бакетов.
#[doc(hidden)]
pub fn validate_shufti_32x16(
    data: &[u8; 32],
    hi: &[u8],
    lo: &[u8],
    bsm_hi: &[u8],
    bsm_lo: &[u8],
    neg: u32,
    valid: u32,
) -> bool {
    let mut nres: u32 = 0;
    for i in 0..32 {
        let l = (data[i] & 0x0f) as usize;
        let h = ((data[i] >> 4) & 0x0f) as usize;
        let t1 = lo[l] & hi[h];
        let t2 = lo[16 + l] & hi[16 + h];
        let result = (t1 & bsm_lo[i]) | (t2 & bsm_hi[i]);
        if result == 0 {
            nres |= 1 << i;
        }
    }
    ((nres ^ neg) & valid) == 0
}

/// Порт `validateMask32`: побайтно `(data & and) == cmp`; итог сверяется с
/// `neg` на valid-позициях. Иная схема, чем 8-байтный `validate_mask`.
#[doc(hidden)]
pub fn validate_mask32(data: &[u8; 32], valid: u32, and_mask: &[u8], cmp_mask: &[u8], neg: u32) -> bool {
    let mut cmp_result: u32 = 0;
    for i in 0..32 {
        if (data[i] & and_mask[i]) != cmp_mask[i] {
            cmp_result |= 1 << i;
        }
    }
    (cmp_result & valid) == (neg & valid)
}

/// Порт `roseCheckShufti32x8` (block mode).
fn check_shufti_32x8(
    buf: &[u8],
    hi: &[u8],
    lo: &[u8],
    bucket: &[u8],
    neg: u32,
    check_offset: i32,
    end: u64,
) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false;
    }
    let off = end as i64 + check_offset as i64;
    let (data, valid) = get_data256(buf, off);
    if valid == 0 {
        return true;
    }
    validate_shufti_32x8(&data, hi, lo, bucket, neg, valid)
}

/// Порт `roseCheckShufti16x16` (block mode; 16 байт данных).
fn check_shufti_16x16(
    buf: &[u8],
    hi: &[u8],
    lo: &[u8],
    bucket: &[u8],
    neg: u32,
    check_offset: i32,
    end: u64,
) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false;
    }
    let off = end as i64 + check_offset as i64;
    let (data, valid) = get_data128(buf, off);
    if valid == 0 {
        return true;
    }
    validate_shufti_16x16(&data, hi, lo, bucket, neg, valid)
}

/// Порт `roseCheckShufti32x16` (block mode).
fn check_shufti_32x16(
    buf: &[u8],
    hi: &[u8],
    lo: &[u8],
    bsm_hi: &[u8],
    bsm_lo: &[u8],
    neg: u32,
    check_offset: i32,
    end: u64,
) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false;
    }
    let off = end as i64 + check_offset as i64;
    let (data, valid) = get_data256(buf, off);
    if valid == 0 {
        return true;
    }
    validate_shufti_32x16(&data, hi, lo, bsm_hi, bsm_lo, neg, valid)
}

/// Порт `roseCheckMask32` (block mode). `validateMask32` при valid=0 даёт true
/// (как в C: «всё в будущем/до истории» → пройдено), явный short-circuit не нужен.
fn check_mask32(
    buf: &[u8],
    and_mask: &[u8],
    cmp_mask: &[u8],
    neg: u32,
    check_offset: i32,
    end: u64,
) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false;
    }
    let off = end as i64 + check_offset as i64;
    let (data, valid) = get_data256(buf, off);
    validate_mask32(&data, valid, and_mask, cmp_mask, neg)
}

/// LE-загрузка `k` (≤8) байт из `buf[off..]` в u64 (младшие k байт), порт
/// `partial_load_u64a`. Хвост за буфером не читаем (вызывающий clamps `k`).
fn load_u64_le_partial(buf: &[u8], off: usize, k: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..k {
        v |= (buf[off + i] as u64) << (i * 8);
    }
    v
}

/// Порт `validateMask` + `posValidateMask`/`negValidateMask` (бит-в-бит).
fn validate_mask(data: u64, valid: u64, and_mask: u64, cmp_mask: u64, neg_mask: u64) -> bool {
    let and_mask = and_mask & valid;
    let cmp_mask = cmp_mask & valid;
    let neg_mask = neg_mask & valid;
    let cmp_result = (data & and_mask) ^ cmp_mask;
    // pos: для не-негированных байт cmp_result должен быть 0.
    let pos_ok = (cmp_result & !neg_mask) == 0;
    // neg: для негированных байт cmp_result должен быть ненулевым.
    const COUNT: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    let check_low = (cmp_result & COUNT).wrapping_add(COUNT);
    let check_all = !(check_low | cmp_result | COUNT);
    let neg_ok = (check_all & neg_mask) == 0;
    pos_ok && neg_ok
}

/// Порт `roseCheckMask` (block mode: buf_offset=0, история пуста → доступна
/// только ветка offset≥0). true = проверка пройдена (продолжаем).
fn check_mask(
    buf: &[u8],
    and_mask: u64,
    cmp_mask: u64,
    neg_mask: u64,
    check_offset: i32,
    end: u64,
) -> bool {
    if check_offset < 0 && (-(check_offset as i64)) as u64 > end {
        return false; // слишком рано
    }
    let off = end as i64 + check_offset as i64;
    let len = buf.len() as i64;
    let (data, valid) = if off + 8 > len {
        if off >= len {
            return true; // целиком в будущем → пройдено
        }
        let c_len = (len - off) as usize; // 1..=7
        let shift_l = 8 - c_len as u32; // байты в будущем (старшие)
        let data = load_u64_le_partial(buf, off as usize, c_len);
        // generateValidMask(shift_l, 0): низкие (8-shift_l) байт валидны.
        let valid = (!0u64 << (shift_l * 8)) >> (shift_l * 8);
        (data, valid)
    } else {
        (load_u64_le_partial(buf, off as usize, 8), !0u64)
    };
    validate_mask(data, valid, and_mask, cmp_mask, neg_mask)
}

/// Порт `roseCheckMediumLiteral` (block mode).
fn check_med_lit(buf: &[u8], lit: &[u8], lit_length: usize, end: u64, nocase: bool) -> bool {
    if (end as usize) < lit_length {
        return false;
    }
    if lit_length > lit.len() {
        return false;
    }
    let start = end as usize - lit_length;
    if end as usize > buf.len() {
        return false;
    }
    let hay = &buf[start..end as usize];
    let needle = &lit[..lit_length];
    if nocase {
        hay.iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    } else {
        hay == needle
    }
}
