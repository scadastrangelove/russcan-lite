//! Safe-ридер сериализованной БД vectorscan (untrusted input!).
//!
//! Формат по `hs_serialize_database`/`db_decode_header` (`database.c`
//! @ a1c107e, версия 5.4.12): упакованный 32-байтовый заголовок (LE):
//!
//! | оффсет | поле     |
//! |--------|----------|
//! | 0      | magic    u32 = 0xdbdbdbdb |
//! | 4      | version  u32 = 0x05040c00 (5.4.12) |
//! | 8      | length   u32 — длина байткода |
//! | 12     | platform u64 |
//! | 20     | crc32    u32 — CRC32C(0, bytecode) без инверсий |
//! | 24     | reserved0 u32 |
//! | 28     | reserved1 u32 |
//! | 32     | байткод (RoseEngine), length байт |
//!
//! Полная длина обязана равняться `104 + length`: C сериализует хвост в
//! `sizeof(struct hs_database)` (104 на LP64) нулями. Значение 104 — часть
//! байткод-контракта и подлежит bindgen-сверке в CI (см. PLAN.md §5).

pub mod crc32c;
pub mod rose;

pub const HS_DB_MAGIC: u32 = 0xdbdb_dbdb;
/// `HS_DB_VERSION` пина: (5<<24)|(4<<16)|(12<<8)|0.
pub const HS_DB_VERSION: u32 = 0x0504_0c00;
/// Оффсет байткода в сериализованном виде.
pub const BYTECODE_OFFSET: usize = 32;
/// `sizeof(struct hs_database)` — оверхед полной длины.
pub const DB_STRUCT_SIZE: usize = 104;

// Платформенные биты (database.h).
pub const HS_PLATFORM_INTEL: u64 = 1;
pub const HS_PLATFORM_ARM: u64 = 2;
pub const HS_PLATFORM_CPU_MASK: u64 = 0x3f;
pub const HS_PLATFORM_NOAVX2: u64 = 4 << 13;
pub const HS_PLATFORM_NOAVX512: u64 = 8 << 13;
pub const HS_PLATFORM_NOAVX512VBMI: u64 = 0x10 << 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// Меньше 32 байт заголовка.
    TooShort,
    BadMagic(u32),
    /// Версия компилятора БД не совпадает с пином контракта.
    BadVersion(u32),
    /// Полная длина не равна `104 + length`.
    LengthMismatch { declared: u32, actual: usize },
    CrcMismatch { stored: u32, computed: u32 },
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DbError::TooShort => write!(f, "буфер короче 32-байтового заголовка"),
            DbError::BadMagic(m) => write!(f, "не hs-база: magic {m:#010x}"),
            DbError::BadVersion(v) => write!(
                f,
                "версия байткода {v:#010x} != пин {HS_DB_VERSION:#010x} (5.4.12)"
            ),
            DbError::LengthMismatch { declared, actual } => write!(
                f,
                "длина не сходится: заявлено length={declared} (итого {}), фактически {actual}",
                *declared as usize + DB_STRUCT_SIZE
            ),
            DbError::CrcMismatch { stored, computed } => write!(
                f,
                "CRC32C не сходится: в заголовке {stored:#010x}, по байткоду {computed:#010x}"
            ),
        }
    }
}

impl std::error::Error for DbError {}

/// Целевая платформа БД: байткод платформозависим (раскладки Teddy и т.п.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform {
    pub raw: u64,
}

impl Platform {
    pub fn cpu_is_intel(self) -> bool {
        self.raw & HS_PLATFORM_CPU_MASK == HS_PLATFORM_INTEL
    }
    pub fn cpu_is_arm(self) -> bool {
        self.raw & HS_PLATFORM_CPU_MASK == HS_PLATFORM_ARM
    }
    /// БД собрана в предположении наличия AVX2 на хосте.
    pub fn wants_avx2(self) -> bool {
        self.raw & HS_PLATFORM_NOAVX2 == 0 && self.cpu_is_intel()
    }
    pub fn wants_avx512(self) -> bool {
        self.raw & HS_PLATFORM_NOAVX512 == 0 && self.cpu_is_intel()
    }
}

/// Распарсенная и проверенная (magic/version/length/CRC) сериализованная БД.
///
/// Держит только заимствованный байткод: дальнейший разбор (RoseEngine) —
/// поверх `bytecode()` с bounds-checked оффсетной арифметикой.
#[derive(Debug)]
pub struct SerializedDb<'a> {
    platform: Platform,
    crc32: u32,
    bytecode: &'a [u8],
}

impl<'a> SerializedDb<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DbError> {
        if bytes.len() < BYTECODE_OFFSET {
            return Err(DbError::TooShort);
        }
        let u32_at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());

        let magic = u32_at(0);
        if magic != HS_DB_MAGIC {
            return Err(DbError::BadMagic(magic));
        }
        let version = u32_at(4);
        if version != HS_DB_VERSION {
            return Err(DbError::BadVersion(version));
        }
        let length = u32_at(8);
        // C: length параметра обязана РАВНЯТЬСЯ sizeof(hs_database) + length.
        if bytes.len() != DB_STRUCT_SIZE + length as usize {
            return Err(DbError::LengthMismatch {
                declared: length,
                actual: bytes.len(),
            });
        }
        let platform = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let crc32 = u32_at(20);
        // reserved0/reserved1 (24, 28) читаются C и игнорируются.

        let bytecode = &bytes[BYTECODE_OFFSET..BYTECODE_OFFSET + length as usize];
        let computed = crc32c::crc32c_raw(0, bytecode);
        if computed != crc32 {
            return Err(DbError::CrcMismatch {
                stored: crc32,
                computed,
            });
        }

        Ok(SerializedDb {
            platform: Platform { raw: platform },
            crc32,
            bytecode,
        })
    }

    pub fn bytecode(&self) -> &'a [u8] {
        self.bytecode
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn crc32(&self) -> u32 {
        self.crc32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Синтетическая БД в нашем же формате (roundtrip-самопроверка;
    /// контракт с настоящим C-выводом закрывает дифф-смок с oracle).
    fn fake_db(bytecode: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; DB_STRUCT_SIZE + bytecode.len()];
        v[0..4].copy_from_slice(&HS_DB_MAGIC.to_le_bytes());
        v[4..8].copy_from_slice(&HS_DB_VERSION.to_le_bytes());
        v[8..12].copy_from_slice(&(bytecode.len() as u32).to_le_bytes());
        v[12..20].copy_from_slice(&2u64.to_le_bytes()); // ARM
        let crc = crc32c::crc32c_raw(0, bytecode);
        v[20..24].copy_from_slice(&crc.to_le_bytes());
        v[BYTECODE_OFFSET..BYTECODE_OFFSET + bytecode.len()].copy_from_slice(bytecode);
        v
    }

    #[test]
    fn parse_roundtrip() {
        let bc: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let blob = fake_db(&bc);
        let db = SerializedDb::parse(&blob).unwrap();
        assert_eq!(db.bytecode(), &bc[..]);
        assert!(db.platform().cpu_is_arm());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(SerializedDb::parse(&[]), Err(DbError::TooShort));
        assert_eq!(
            SerializedDb::parse(&[0u8; 200]).unwrap_err(),
            DbError::BadMagic(0)
        );

        let mut blob = fake_db(b"bytecode");
        blob[5] = 0x99;
        assert!(matches!(
            SerializedDb::parse(&blob).unwrap_err(),
            DbError::BadVersion(_)
        ));

        let mut blob = fake_db(b"bytecode");
        blob.push(0);
        assert!(matches!(
            SerializedDb::parse(&blob).unwrap_err(),
            DbError::LengthMismatch { .. }
        ));

        let mut blob = fake_db(b"bytecode");
        blob[35] ^= 1; // внутри байткода (32..40)
        assert!(matches!(
            SerializedDb::parse(&blob).unwrap_err(),
            DbError::CrcMismatch { .. }
        ));
    }
}

// PartialEq для удобства тестов parse.
impl PartialEq for SerializedDb<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.platform == other.platform && self.crc32 == other.crc32 && self.bytecode == other.bytecode
    }
}
