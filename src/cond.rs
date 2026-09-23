//! Condition codes, shared by every conditional form in the instruction set.
//!
//! One type, used by the 16-bit `B<cond>` (T1), the 32-bit `B<cond>.W` (T3),
//! and `IT`. The bit values are the architectural ones (ARM DDI 0403E.e
//! Table A7-1), so [`Cond::bits`] and [`Cond::from_bits`] are the encoding.

/// An ARM condition code.
///
/// `0b1110` (`AL`, always) is [`Cond::Al`]. `0b1111` is **not** a condition:
/// in the 16-bit branch space it is `SVC`, and in the 32-bit space it is
/// reserved — so [`Cond::from_bits`] rejects it rather than inventing a
/// fifteenth condition.
///
/// ```
/// use thumb_asm::Cond;
///
/// assert_eq!(Cond::from_bits(0b0001), Some(Cond::Ne));
/// assert_eq!(Cond::Ne.bits(), 0b0001);
/// assert_eq!(Cond::Ne.invert(), Cond::Eq);
/// assert_eq!(Cond::Hs.to_string(), "hs");
/// assert_eq!(Cond::from_bits(0b1111), None); // not a condition
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cond {
    /// Equal — `Z == 1`.
    Eq,
    /// Not equal — `Z == 0`.
    Ne,
    /// Unsigned higher or same, also spelled `CS` — `C == 1`.
    Hs,
    /// Unsigned lower, also spelled `CC` — `C == 0`.
    Lo,
    /// Negative — `N == 1`.
    Mi,
    /// Positive or zero — `N == 0`.
    Pl,
    /// Overflow — `V == 1`.
    Vs,
    /// No overflow — `V == 0`.
    Vc,
    /// Unsigned higher — `C == 1 && Z == 0`.
    Hi,
    /// Unsigned lower or same — `C == 0 || Z == 1`.
    Ls,
    /// Signed greater than or equal — `N == V`.
    Ge,
    /// Signed less than — `N != V`.
    Lt,
    /// Signed greater than — `Z == 0 && N == V`.
    Gt,
    /// Signed less than or equal — `Z == 1 || N != V`.
    Le,
    /// Always. Encodable in `IT` and in `B<cond>.W`, but never in the 16-bit
    /// `B<cond>` (there, `0b1110` is the permanently-undefined `UDF` space).
    Al,
}

impl Cond {
    /// The condition with this 4-bit encoding, or `None` for `0b1111`, which
    /// the architecture does not define as a condition.
    pub fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits & 0xF {
            0b0000 => Cond::Eq,
            0b0001 => Cond::Ne,
            0b0010 => Cond::Hs,
            0b0011 => Cond::Lo,
            0b0100 => Cond::Mi,
            0b0101 => Cond::Pl,
            0b0110 => Cond::Vs,
            0b0111 => Cond::Vc,
            0b1000 => Cond::Hi,
            0b1001 => Cond::Ls,
            0b1010 => Cond::Ge,
            0b1011 => Cond::Lt,
            0b1100 => Cond::Gt,
            0b1101 => Cond::Le,
            0b1110 => Cond::Al,
            _ => return None,
        })
    }

    /// This condition's 4-bit encoding.
    pub fn bits(self) -> u8 {
        match self {
            Cond::Eq => 0b0000,
            Cond::Ne => 0b0001,
            Cond::Hs => 0b0010,
            Cond::Lo => 0b0011,
            Cond::Mi => 0b0100,
            Cond::Pl => 0b0101,
            Cond::Vs => 0b0110,
            Cond::Vc => 0b0111,
            Cond::Hi => 0b1000,
            Cond::Ls => 0b1001,
            Cond::Ge => 0b1010,
            Cond::Lt => 0b1011,
            Cond::Gt => 0b1100,
            Cond::Le => 0b1101,
            Cond::Al => 0b1110,
        }
    }

    /// The condition that is true exactly when this one is false — i.e. this
    /// condition's encoding with bit 0 flipped. `AL` inverts to itself, since
    /// `0b1111` is not a condition; callers branching on an inverted `AL`
    /// should emit nothing at all rather than an always-false branch.
    pub fn invert(self) -> Self {
        match self {
            Cond::Al => Cond::Al,
            other => Cond::from_bits(other.bits() ^ 1).unwrap_or(Cond::Al),
        }
    }

    /// The UAL mnemonic suffix (`"eq"`, `"ne"`, …). `AL` renders as the empty
    /// string, which is how it is written in assembly.
    pub fn suffix(self) -> &'static str {
        match self {
            Cond::Eq => "eq",
            Cond::Ne => "ne",
            Cond::Hs => "hs",
            Cond::Lo => "lo",
            Cond::Mi => "mi",
            Cond::Pl => "pl",
            Cond::Vs => "vs",
            Cond::Vc => "vc",
            Cond::Hi => "hi",
            Cond::Ls => "ls",
            Cond::Ge => "ge",
            Cond::Lt => "lt",
            Cond::Gt => "gt",
            Cond::Le => "le",
            Cond::Al => "",
        }
    }
}

impl std::fmt::Display for Cond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.suffix())
    }
}
