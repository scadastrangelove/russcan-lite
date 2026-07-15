//! CRC32C (Castagnoli) в варианте vectorscan: БЕЗ стандартных xor-in/xor-out.
//!
//! `db_check_crc` вызывает `Crc32c_ComputeBuf(0, bytecode, len)`; и software-
//! (slicing-by-8, `crc32.c`), и SSE4.2-пути считают сырую рефлектированную
//! рекуррентность с инициализацией переданным значением (0) и без финальной
//! инверсии. Здесь — эквивалентная табличная версия (скорость не важна:
//! только загрузка БД).

const POLY_REFLECTED: u32 = 0x82F6_3B78; // 0x1EDC6F41 в reversed-форме

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                POLY_REFLECTED ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = make_table();

/// Порт `Crc32c_ComputeBuf`: сырой CRC32C от `init` без финальной инверсии.
pub fn crc32c_raw(init: u32, data: &[u8]) -> u32 {
    let mut crc = init;
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Валидация таблицы: стандартный CRC-32C (iSCSI, с xor-in/out) от
    /// "123456789" — известный вектор 0xE3069283. Vectorscan использует ту же
    /// таблицу, но с init=0 и без инверсии.
    #[test]
    fn table_matches_iscsi_vector() {
        let raw = crc32c_raw(0xffff_ffff, b"123456789");
        assert_eq!(raw ^ 0xffff_ffff, 0xE306_9283);
    }

    #[test]
    fn empty_is_identity() {
        assert_eq!(crc32c_raw(0, b""), 0);
        assert_eq!(crc32c_raw(0x1234_5678, b""), 0x1234_5678);
    }
}
