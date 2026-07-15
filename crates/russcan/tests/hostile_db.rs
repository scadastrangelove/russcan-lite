//! Регресс-тесты защиты от враждебной (CRC-валидной) БД: подтверждают, что
//! confirm-регион валидируется в `FdrTable::parse`, поэтому испорченные
//! confirm-оффсеты ОТКЛОНЯЮТСЯ на разборе, а не приводят к OOB в hot-path.
//! Закрывает vuln-scan F-001/002/004/009 (см. TRIAGE.md). Оракул не нужен —
//! используем запиненную FDR-БД из fixtures.

use russcan_bytecode::rose::RoseEngine;
use russcan_bytecode::SerializedDb;
use russcan_hwlm::fdr::FdrTable;

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
