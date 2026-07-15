//! Доступ к полям `RoseEngine` и локализация floating-FDR внутри байткода.
//!
//! Оффсеты сняты `tools/layout_probe` на пине vectorscan 5.4.12 (LP64). Поля
//! `RoseEngine` — только фиксированной ширины (u8/u32/u64, `rose_group=u64`),
//! указателей нет → раскладка идентична на aarch64 и x86_64. Это часть
//! байткод-контракта; сверка обеих арок — в `layout_arm.json`/`layout_x86.json`
//! и подлежит bindgen-CI (PLAN.md §5).

/// Смещения полей `struct RoseEngine` (в байтах от начала байткода).
mod re {
    pub const PURE_LITERAL: usize = 0; // u8
    pub const RUNTIME_IMPL: usize = 4; // u8
    pub const MODE: usize = 12; // u32
    pub const SMALL_WRITE_OFFSET: usize = 84; // u32
    pub const AMATCHER_OFFSET: usize = 88; // u32
    pub const EMATCHER_OFFSET: usize = 92; // u32
    pub const FMATCHER_OFFSET: usize = 96; // u32
    pub const LONG_LIT_TABLE_OFFSET: usize = 108; // u32
    pub const ACTIVE_ARRAY_COUNT: usize = 148; // u32
    pub const QUEUE_COUNT: usize = 156; // u32
    pub const EOD_PROGRAM_OFFSET: usize = 184; // u32
    pub const FLOATING_MIN_LIT_MATCH_OFFSET: usize = 232; // u32
    pub const INITIAL_GROUPS: usize = 240; // u64 (rose_group)
    pub const FLOATING_GROUP_MASK: usize = 248; // u64
    pub const DELAY_PROGRAM_OFFSET: usize = 140; // u32
    pub const SIZE: usize = 256; // u32
    pub const DELAY_COUNT: usize = 260; // u32
    pub const ANCHORED_COUNT: usize = 268; // u32
    pub const TOTAL_NUM_LITERALS: usize = 388; // u32
    // NFA-машинерия (Ф4, для outfix-пути; probe).
    pub const NFA_INFO_OFFSET: usize = 236; // u32: массив NfaInfo
    pub const OUTFIX_BEGIN_QUEUE: usize = 396; // u32
    pub const OUTFIX_END_QUEUE: usize = 400; // u32
}

/// `sizeof(struct NfaInfo)`; `nfaOffset` — первое поле (probe).
pub const NFA_INFO_SIZE: usize = 20;

/// `#define ROSE_RUNTIME_FULL_ROSE 0` / `PURE_LITERAL 1` (rose_internal.h).
pub const ROSE_RUNTIME_FULL_ROSE: u8 = 0;
pub const ROSE_RUNTIME_PURE_LITERAL: u8 = 1;
/// Оптимизированный путь БД из единственного outfix-NFA (без литералов).
pub const ROSE_RUNTIME_SINGLE_OUTFIX: u8 = 2;
/// `HS_MODE_BLOCK` (hs_compile.h).
pub const HS_MODE_BLOCK: u32 = 1;

/// `HWLM_ENGINE_FDR` (hwlm_internal.h).
pub const HWLM_ENGINE_FDR: u8 = 12;
/// `HWLM_ENGINE_NOOD` (hwlm_internal.h).
pub const HWLM_ENGINE_NOOD: u8 = 16;

/// `ROUNDUP_CL(sizeof(struct HWLM))` — оффсет FDR-данных за заголовком HWLM.
/// sizeof(HWLM)=224 (probe) → округление до кэшлинии 64 = 256. Часть контракта.
pub const HWLM_DATA_OFFSET: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoseError {
    /// Байткод короче, чем поле, к которому обращаемся.
    Truncated,
    /// Не block mode — вне скоупа FDR-only MVP.
    NotBlockMode(u32),
    /// runtimeImpl вне {PURE_LITERAL, FULL_ROSE}.
    UnsupportedRuntime(u8),
    /// БД содержит машинерию за пределами floating-литералов (anchored/NFA/
    /// long-lit/EOD) — нужен полный Rose, вне скоупа. Поле = что именно.
    NeedsFullRose(&'static str),
    /// fmatcherOffset == 0 — нет floating-таблицы.
    NoFloatingMatcher,
    /// HWLM-движок не FDR (например noodle) — обрабатывается отдельно.
    NotFdr(u8),
    /// Оффсет за пределами байткода.
    OffsetOutOfRange { off: usize, len: usize },
}

impl core::fmt::Display for RoseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RoseError::Truncated => write!(f, "байткод усечён"),
            RoseError::NotBlockMode(m) => write!(f, "mode={m} != BLOCK(1)"),
            RoseError::UnsupportedRuntime(i) => {
                write!(f, "runtimeImpl={i} вне {{PURE_LITERAL,FULL_ROSE}}")
            }
            RoseError::NeedsFullRose(what) => {
                write!(f, "БД требует полный Rose ({what}) — вне floating-скоупа")
            }
            RoseError::NoFloatingMatcher => write!(f, "fmatcherOffset=0"),
            RoseError::NotFdr(t) => write!(f, "HWLM type={t} != FDR(12)"),
            RoseError::OffsetOutOfRange { off, len } => {
                write!(f, "оффсет {off} вне байткода длины {len}")
            }
        }
    }
}
impl std::error::Error for RoseError {}

/// Разобранный view над байткодом `RoseEngine` для floating-литерального
/// block-скана (PURE_LITERAL или FULL_ROSE без anchored/NFA-машинерии).
#[derive(Debug, Clone, Copy)]
pub struct RoseEngine<'a> {
    bc: &'a [u8],
    pub pure_literal: u8,
    pub runtime_impl: u8,
    pub mode: u32,
    pub fmatcher_offset: u32,
    pub floating_min_lit_match_offset: u32,
    pub initial_groups: u64,
    pub floating_group_mask: u64,
    pub size: u32,
    pub total_num_literals: u32,
    /// smallWriteOffset (≠0 → есть smallwrite-фастпас для коротких буферов;
    /// для floating-only БД он избыточен, floating покрывает те же литералы).
    pub small_write_offset: u32,
    /// delay_count (≠0 → есть отложенные литералы, нужен PUSH_DELAYED-путь).
    pub delay_count: u32,
    /// Оффсет таблицы u32-программ отложенных литералов (delayProgramOffset).
    pub delay_program_offset: u32,
    // NFA-машинерия (Ф4). nfaInfoOffset → массив NfaInfo; outfix-очереди
    // [begin,end) индексируют его. Заполняются и `parse`, и `parse_allow_nfa`.
    pub nfa_info_offset: u32,
    pub outfix_begin_queue: u32,
    pub outfix_end_queue: u32,
}

impl<'a> RoseEngine<'a> {
    /// Разбирает заголовок RoseEngine. Принимает block-mode БД, где матчи
    /// приходят ТОЛЬКО из floating-таблицы: PURE_LITERAL, либо FULL_ROSE без
    /// anchored/eod-literal/long-lit/NFA-очередей. Всё прочее — fail-fast
    /// `NeedsFullRose` (не молчаливый неверный результат).
    pub fn parse(bc: &'a [u8]) -> Result<Self, RoseError> {
        // vuln-scan F-101: read_header декодирует поля вплоть до OUTFIX_END_QUEUE
        // (оффсет 400, чтение 400..404), поэтому гвард обязан покрывать 404, а не
        // TOTAL_NUM_LITERALS+4 (=392) — иначе bc длиной 392..=403 проходит проверку
        // и паникует на slice-index в read_header (враждебная CRC-валидная БД).
        let need = re::OUTFIX_END_QUEUE + 4;
        if bc.len() < need {
            return Err(RoseError::Truncated);
        }
        let u32_at = |o: usize| u32::from_le_bytes(bc[o..o + 4].try_into().unwrap());

        let e = Self::read_header(bc);
        if e.mode != HS_MODE_BLOCK {
            return Err(RoseError::NotBlockMode(e.mode));
        }
        if !matches!(e.runtime_impl, ROSE_RUNTIME_PURE_LITERAL | ROSE_RUNTIME_FULL_ROSE) {
            return Err(RoseError::UnsupportedRuntime(e.runtime_impl));
        }
        // Гарды: матчи должны приходить ТОЛЬКО из floating-таблицы.
        // Любая другая машинерия → нужен полный Rose (fail-fast).
        for (off, what) in [
            (re::AMATCHER_OFFSET, "anchored-matcher"),
            (re::EMATCHER_OFFSET, "eod-matcher"),
            (re::LONG_LIT_TABLE_OFFSET, "long-literal-table"),
            (re::ACTIVE_ARRAY_COUNT, "nfa-active-array"),
            (re::QUEUE_COUNT, "nfa-queues"),
            (re::EOD_PROGRAM_OFFSET, "eod-program"),
            (re::ANCHORED_COUNT, "anchored-literals"),
        ] {
            if u32_at(off) != 0 {
                return Err(RoseError::NeedsFullRose(what));
            }
        }
        Ok(e)
    }

    /// Как [`RoseEngine::parse`], но допускает NFA-очереди (для outfix-пути
    /// Ф4). Прочие гарды сохранены: block mode, поддержанный runtime, без
    /// anchored/eod-matcher/long-lit/delay/eod-программы. Матчи приходят из
    /// floating-таблицы И/ИЛИ из outfix-NFA (см. [`RoseEngine::outfix_nfas`]).
    pub fn parse_allow_nfa(bc: &'a [u8]) -> Result<Self, RoseError> {
        // vuln-scan F-101: read_header декодирует поля вплоть до OUTFIX_END_QUEUE
        // (оффсет 400, чтение 400..404), поэтому гвард обязан покрывать 404, а не
        // TOTAL_NUM_LITERALS+4 (=392) — иначе bc длиной 392..=403 проходит проверку
        // и паникует на slice-index в read_header (враждебная CRC-валидная БД).
        let need = re::OUTFIX_END_QUEUE + 4;
        if bc.len() < need {
            return Err(RoseError::Truncated);
        }
        let u32_at = |o: usize| u32::from_le_bytes(bc[o..o + 4].try_into().unwrap());
        let e = Self::read_header(bc);
        if e.mode != HS_MODE_BLOCK {
            return Err(RoseError::NotBlockMode(e.mode));
        }
        // SINGLE_OUTFIX — целевой путь; FULL_ROSE — если outfix живёт рядом с
        // (пустыми на матчи) литералами. PURE_LITERAL сюда не идёт.
        if !matches!(
            e.runtime_impl,
            ROSE_RUNTIME_FULL_ROSE | ROSE_RUNTIME_SINGLE_OUTFIX
        ) {
            return Err(RoseError::UnsupportedRuntime(e.runtime_impl));
        }
        // NFA-очереди РАЗРЕШЕНЫ; остальная не-outfix машинерия — fail-fast.
        for (off, what) in [
            (re::AMATCHER_OFFSET, "anchored-matcher"),
            (re::EMATCHER_OFFSET, "eod-matcher"),
            (re::LONG_LIT_TABLE_OFFSET, "long-literal-table"),
            (re::EOD_PROGRAM_OFFSET, "eod-program"),
            (re::ANCHORED_COUNT, "anchored-literals"),
            (re::DELAY_COUNT, "delayed-literals"),
        ] {
            if u32_at(off) != 0 {
                return Err(RoseError::NeedsFullRose(what));
            }
        }
        // Только outfix-NFA (leftfix/suffix-очереди вне outfix-диапазона — позже).
        let q_count = u32_at(re::QUEUE_COUNT);
        if q_count != 0 && e.outfix_end_queue > q_count {
            return Err(RoseError::NeedsFullRose("nfa-queue вне outfix-диапазона"));
        }
        Ok(e)
    }

    fn read_header(bc: &'a [u8]) -> Self {
        let u32_at = |o: usize| u32::from_le_bytes(bc[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(bc[o..o + 8].try_into().unwrap());
        RoseEngine {
            bc,
            pure_literal: bc[re::PURE_LITERAL],
            runtime_impl: bc[re::RUNTIME_IMPL],
            mode: u32_at(re::MODE),
            fmatcher_offset: u32_at(re::FMATCHER_OFFSET),
            floating_min_lit_match_offset: u32_at(re::FLOATING_MIN_LIT_MATCH_OFFSET),
            initial_groups: u64_at(re::INITIAL_GROUPS),
            floating_group_mask: u64_at(re::FLOATING_GROUP_MASK),
            size: u32_at(re::SIZE),
            total_num_literals: u32_at(re::TOTAL_NUM_LITERALS),
            small_write_offset: u32_at(re::SMALL_WRITE_OFFSET),
            delay_count: u32_at(re::DELAY_COUNT),
            delay_program_offset: u32_at(re::DELAY_PROGRAM_OFFSET),
            nfa_info_offset: u32_at(re::NFA_INFO_OFFSET),
            outfix_begin_queue: u32_at(re::OUTFIX_BEGIN_QUEUE),
            outfix_end_queue: u32_at(re::OUTFIX_END_QUEUE),
        }
    }

    /// Оффсеты полных байтов NFA (заголовок + impl) всех outfix-движков —
    /// `NfaInfo[qi].nfaOffset` для `qi in [outfixBeginQueue, outfixEndQueue)`.
    pub fn outfix_nfas(&self) -> Result<Vec<&'a [u8]>, RoseError> {
        let mut out = Vec::new();
        for qi in self.outfix_begin_queue..self.outfix_end_queue {
            let info = self.nfa_info_offset as usize + qi as usize * NFA_INFO_SIZE;
            let nfa_off = self
                .bc
                .get(info..info + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .ok_or(RoseError::OffsetOutOfRange {
                    off: info,
                    len: self.bc.len(),
                })? as usize;
            let bytes = self.bc.get(nfa_off..).ok_or(RoseError::OffsetOutOfRange {
                off: nfa_off,
                len: self.bc.len(),
            })?;
            out.push(bytes);
        }
        Ok(out)
    }

    /// Полные байты NFA (заголовок + impl) движка очереди `qi` — порт
    /// `getNfaByQueue(t, qi)`: читает `NfaInfo[qi].nfaOffset` и режет байткод.
    /// Используется для leftfix (CHECK_PREFIX/INFIX) и suffix.
    pub fn nfa_by_queue(&self, qi: u32) -> Result<&'a [u8], RoseError> {
        let info = self.nfa_info_offset as usize + qi as usize * NFA_INFO_SIZE;
        let nfa_off = self
            .bc
            .get(info..info + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .ok_or(RoseError::OffsetOutOfRange {
                off: info,
                len: self.bc.len(),
            })? as usize;
        self.bc.get(nfa_off..).ok_or(RoseError::OffsetOutOfRange {
            off: nfa_off,
            len: self.bc.len(),
        })
    }

    /// Весь байткод (база оффсетов `getByOffset`).
    pub fn bytecode(&self) -> &'a [u8] {
        self.bc
    }

    /// Тип HWLM-движка floating-таблицы (FDR/NOOD).
    pub fn floating_hwlm_type(&self) -> Result<u8, RoseError> {
        let off = self.fmatcher_offset as usize;
        if off == 0 {
            return Err(RoseError::NoFloatingMatcher);
        }
        self.bc.get(off).copied().ok_or(RoseError::OffsetOutOfRange {
            off,
            len: self.bc.len(),
        })
    }

    /// Слайс сериализованной FDR-таблицы (то, что ест `FdrTable::parse`).
    /// Начинается за заголовком HWLM (`HWLM_DATA_OFFSET`).
    pub fn floating_fdr_table(&self) -> Result<&'a [u8], RoseError> {
        if self.floating_hwlm_type()? != HWLM_ENGINE_FDR {
            return Err(RoseError::NotFdr(self.floating_hwlm_type()?));
        }
        let start = self.fmatcher_offset as usize + HWLM_DATA_OFFSET;
        self.bc.get(start..).ok_or(RoseError::OffsetOutOfRange {
            off: start,
            len: self.bc.len(),
        })
    }

    /// Слайс данных floating-матчера (за заголовком HWLM), независимо от типа
    /// (FDR/Teddy/noodle). Диспетчер выбирает движок по `floating_hwlm_type`
    /// и (для FDR/Teddy) по engineID первых 4 байт слайса.
    pub fn floating_matcher_table(&self) -> Result<&'a [u8], RoseError> {
        self.floating_hwlm_type()?; // валидирует fmatcherOffset != 0
        let start = self.fmatcher_offset as usize + HWLM_DATA_OFFSET;
        self.bc.get(start..).ok_or(RoseError::OffsetOutOfRange {
            off: start,
            len: self.bc.len(),
        })
    }

    /// Программа отложенного литерала `index` (`delayProgramOffset[index]`).
    pub fn delay_program(&self, index: u32) -> Result<u32, RoseError> {
        let off = self.delay_program_offset as usize + index as usize * 4;
        self.bc
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .ok_or(RoseError::OffsetOutOfRange {
                off,
                len: self.bc.len(),
            })
    }

    /// `getByOffset(t, off)` — срез байткода начиная с `off`.
    pub fn by_offset(&self, off: usize) -> Result<&'a [u8], RoseError> {
        self.bc.get(off..).ok_or(RoseError::OffsetOutOfRange {
            off,
            len: self.bc.len(),
        })
    }
}
