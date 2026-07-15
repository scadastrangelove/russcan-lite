//! Регресс-тесты защиты от враждебной (CRC-валидной) БД: подтверждают, что
//! confirm-регион валидируется в `FdrTable::parse`, поэтому испорченные
//! confirm-оффсеты ОТКЛОНЯЮТСЯ на разборе, а не приводят к OOB в hot-path.
//! Закрывает vuln-scan F-001/002/004/009 (см. TRIAGE.md). Оракул не нужен —
//! используем запиненную FDR-БД из fixtures.

use russcan::Database;
use russcan_bytecode::rose::RoseEngine;
use russcan_bytecode::SerializedDb;
use russcan_hwlm::fdr::FdrTable;
use russcan_hwlm::ScanCtl;

/// Извлекает байты floating FDR-таблицы из сериализованной БД (тот же путь, что
/// `Database::load`).
fn fdr_table_bytes(db: &[u8]) -> Vec<u8> {
    let sdb = SerializedDb::parse(db).expect("parse serialized db");
    let rose = RoseEngine::parse(sdb.bytecode()).expect("parse rose");
    rose.floating_matcher_table()
        .expect("floating matcher table")
        .to_vec()
}

const REAL_DB: &[u8] = include_bytes!("fixtures/realpack.db");

#[test]
fn valid_fdr_table_parses() {
    let table = fdr_table_bytes(REAL_DB);
    // realpack = plain FDR (engineID 0); валидная таблица разбирается.
    assert!(
        FdrTable::parse(&table).is_ok(),
        "запиненная валидная FDR-таблица должна разбираться"
    );
}

#[test]
fn hostile_confirm_offset_rejected_at_parse() {
    let mut table = fdr_table_bytes(REAL_DB);
    assert!(FdrTable::parse(&table).is_ok(), "baseline: валидна до порчи");

    // conf_offset = u32 @ 16. Портим confirm-бакет 0 (`cf`) на большое значение:
    // fdrc = conf_offset + cf уводит за пределы таблицы. До фикса это давало
    // unchecked OOB-чтение в do_confirm; теперь parse обязан вернуть Err.
    let conf_offset = u32::from_le_bytes(table[16..20].try_into().unwrap()) as usize;
    table[conf_offset..conf_offset + 4].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());

    assert!(
        FdrTable::parse(&table).is_err(),
        "враждебный confirm-оффсет должен отклоняться на разборе, а не давать OOB"
    );
}

#[test]
fn hostile_table_size_rejected() {
    // Раздутый заголовочный `size` (u32 @ 4) сверх длины буфера → Truncated,
    // а не срез за пределы (защита среза `bytes[..size]`).
    let mut table = fdr_table_bytes(REAL_DB);
    let huge = (table.len() as u32).saturating_add(4096);
    table[4..8].copy_from_slice(&huge.to_le_bytes());
    assert!(
        FdrTable::parse(&table).is_err(),
        "size > buffer должен отклоняться (Truncated)"
    );
}

/// tiny-buffer safety: скан буферов длиной 0..=40 не паникует и не underflow'ит.
/// Пинит границы FDR-зон (`create_short/start/end_zone`): `start = z_end -
/// ITER_BYTES` не уходит в underflow (start = copy_len ≥ 1), а unsafe-загрузки
/// зоны ограничены гвардом `it + ITER_BYTES <= z.end` внутри 64-байтного
/// `copied`-буфера. overflow-checks в test-сборке превращают любой
/// wrapping_sub-underflow в панику → падение теста. Закрывает автономную
/// гипотезу rust-in-peace («z.start < 8 на малых телах → OOB») как R1-FP:
/// unsafe-чтение доминируется проверенным инвариантом.
#[test]
fn tiny_buffers_scan_without_panic() {
    let db = Database::load(REAL_DB).expect("load realpack db");
    // 0..=40 покрывает short-зону (len ≤ 16), start/end-границы и первую main-зону.
    for len in 0usize..=40 {
        for &b in &[0x00u8, b'a', 0xff] {
            let data = vec![b; len];
            db.scan_block(&data, &mut |_, _| ScanCtl::Continue)
                .unwrap_or_else(|e| panic!("len={len} byte={b:#x}: scan_block Err {e}"));
        }
    }
}
