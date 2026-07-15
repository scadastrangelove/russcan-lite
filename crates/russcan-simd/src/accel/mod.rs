//! Публичный API accel-примитивов с рантайм-диспатчем бэкенда.
//!
//! Семантика возвратов (везде `Option<usize>` вместо C-шных указателей):
//! * `*_exec` вперёд — индекс первого байта-матча, `None` — нет матча;
//! * `r*_exec` назад — индекс последнего байта-матча;
//! * [`shufti_double_exec`] — позиция остановки сканера (первый символ пары
//!   либо resume-точка `len-1`, см. фикс #402 апстрима).
//!
//! Пустой буфер — всегда `None` (C требует `buf < buf_end`; мы мягче).

pub mod generic;
pub mod masks;
pub mod reference;

#[cfg(test)]
mod tests;

macro_rules! dispatch_fns {
    ($( $(#[$doc:meta])* $name:ident( $($arg:ident : $ty:ty),* ) );* $(;)?) => {
        $(
            $(#[$doc])*
            #[inline]
            pub fn $name($($arg: $ty,)* buf: &[u8]) -> Option<usize> {
                if buf.is_empty() {
                    return None;
                }
                imp::$name($($arg,)* buf)
            }
        )*

        #[cfg(target_arch = "x86_64")]
        mod imp {
            $(
                #[inline]
                pub fn $name($($arg: $ty,)* buf: &[u8]) -> Option<usize> {
                    if std::arch::is_x86_feature_detected!("ssse3") {
                        // SAFETY: SSSE3 подтверждён рантайм-детектом.
                        unsafe { ssse3::$name($($arg,)* buf) }
                    } else {
                        // SAFETY: скалярный бэкенд не требует ISA.
                        unsafe {
                            crate::accel::generic::$name::<crate::V128Scalar>($($arg,)* buf)
                        }
                    }
                }
            )*

            mod ssse3 {
                $(
                    #[target_feature(enable = "ssse3")]
                    pub unsafe fn $name($($arg: $ty,)* buf: &[u8]) -> Option<usize> {
                        crate::accel::generic::$name::<crate::V128Sse>($($arg,)* buf)
                    }
                )*
            }
        }

        #[cfg(target_arch = "aarch64")]
        mod imp {
            $(
                #[inline]
                pub fn $name($($arg: $ty,)* buf: &[u8]) -> Option<usize> {
                    // SAFETY: NEON — обязательная часть aarch64.
                    unsafe {
                        crate::accel::generic::$name::<crate::V128Neon>($($arg,)* buf)
                    }
                }
            )*
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        mod imp {
            $(
                #[inline]
                pub fn $name($($arg: $ty,)* buf: &[u8]) -> Option<usize> {
                    // SAFETY: скалярный бэкенд не требует ISA.
                    unsafe {
                        crate::accel::generic::$name::<crate::V128Scalar>($($arg,)* buf)
                    }
                }
            )*
        }
    };
}

dispatch_fns! {
    /// Первый байт, принадлежащий shufti-классу (`lo[b&0xf] & hi[b>>4] != 0`).
    shufti_exec(mask_lo: &[u8; 16], mask_hi: &[u8; 16]);
    /// Последний байт, принадлежащий shufti-классу.
    rshufti_exec(mask_lo: &[u8; 16], mask_hi: &[u8; 16]);
    /// Двойной shufti: остановка на первом символе пары или resume-точке.
    shufti_double_exec(m1_lo: &[u8; 16], m1_hi: &[u8; 16], m2_lo: &[u8; 16], m2_hi: &[u8; 16]);
    /// Первый байт, принадлежащий truffle-классу (полные 256 значений).
    truffle_exec(mask_highclear: &[u8; 16], mask_highset: &[u8; 16]);
    /// Последний байт, принадлежащий truffle-классу.
    rtruffle_exec(mask_highclear: &[u8; 16], mask_highset: &[u8; 16]);
    /// Первое вхождение байта `c` (nocase: ASCII-регистронезависимо).
    vermicelli_exec(c: u8, nocase: bool);
    /// Первый байт, НЕ равный `c`.
    nvermicelli_exec(c: u8, nocase: bool);
    /// Последнее вхождение байта `c`.
    rvermicelli_exec(c: u8, nocase: bool);
    /// Последний байт, НЕ равный `c`.
    rnvermicelli_exec(c: u8, nocase: bool);
}
