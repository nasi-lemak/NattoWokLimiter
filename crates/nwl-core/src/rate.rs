//! Human-friendly byte sizes and transfer rates.
//!
//! Accepted forms (case-insensitive, whitespace optional):
//! `500`, `500B`, `64k`, `64KB`, `1.5MiB`, `2GB` for sizes and the same with a
//! `/s` or `ps` suffix for rates (`1.5MB/s`, `512KBps`). Bit units are accepted
//! for rates: `10Mbit`, `10Mbps`, `100kbit/s`.
//!
//! Decimal prefixes (`k`, `M`, `G`) are powers of 1000, binary prefixes
//! (`Ki`, `Mi`, `Gi`) are powers of 1024, matching what users see from ISPs and
//! from OS file managers respectively.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} `{input}`: {reason}")]
pub struct ParseError {
    kind: &'static str,
    input: String,
    reason: &'static str,
}

/// A transfer rate in bytes per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rate(pub u64);

/// An amount of data in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(pub u64);

impl Rate {
    pub const fn bytes_per_sec(self) -> u64 {
        self.0
    }
}

fn parse_quantity(input: &str, kind: &'static str, allow_bits: bool) -> Result<u64, ParseError> {
    let err = |reason| ParseError { kind, input: input.to_string(), reason };
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() {
        return Err(err("empty"));
    }
    let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num.parse().map_err(|_| err("expected a number"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(err("must be a non-negative number"));
    }

    let mut unit = unit.to_string();
    if allow_bits {
        for suffix in ["/s", "ps"] {
            if unit.len() > suffix.len() && unit.to_ascii_lowercase().ends_with(suffix) {
                unit.truncate(unit.len() - suffix.len());
                break;
            }
        }
    }

    // Bits vs bytes: "bit" always means bits and "B" bytes. A lowercase "b"
    // means bits for rates (networking convention: "10Mbps", "64kb/s") and
    // bytes for sizes, where people write "5kb" meaning kilobytes.
    let lower = unit.to_ascii_lowercase();
    let (prefix, is_bits) = if let Some(p) = lower.strip_suffix("bit") {
        (p.to_string(), true)
    } else if let Some(p) = unit.strip_suffix('b') {
        (p.to_ascii_lowercase(), allow_bits)
    } else if let Some(p) = unit.strip_suffix('B') {
        (p.to_ascii_lowercase(), false)
    } else {
        (lower, false)
    };
    if is_bits && !allow_bits {
        return Err(err("bit units are only valid for rates"));
    }

    let multiplier: f64 = match prefix.as_str() {
        "" => 1.0,
        "k" => 1e3,
        "m" => 1e6,
        "g" => 1e9,
        "t" => 1e12,
        "ki" => 1024.0,
        "mi" => 1024.0 * 1024.0,
        "gi" => 1024.0 * 1024.0 * 1024.0,
        "ti" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(err("unknown unit")),
    };
    let bytes = value * multiplier / if is_bits { 8.0 } else { 1.0 };
    if bytes > u64::MAX as f64 {
        return Err(err("too large"));
    }
    Ok(bytes.round() as u64)
}

impl FromStr for Rate {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_quantity(s, "rate", true).map(Rate)
    }
}

impl FromStr for ByteSize {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_quantity(s, "size", false).map(ByteSize)
    }
}

/// Formats a byte count with a decimal prefix, e.g. `1.50 MB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    // Compare after rounding to the printed precision, so 999_999 bytes
    // prints as "1.00 MB" rather than "1000.00 kB".
    while unit < UNITS.len() - 1 && (value >= 1000.0 || (unit > 0 && value >= 999.995)) {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_bytes(self.0))
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/s", format_bytes(self.0))
    }
}

macro_rules! string_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                // Serialize as a plain integer so the API stays machine friendly;
                // deserialization accepts either integers or human strings.
                s.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(untagged)]
                enum Raw {
                    Int(u64),
                    Str(String),
                }
                match Raw::deserialize(d)? {
                    Raw::Int(v) => Ok(Self(v)),
                    Raw::Str(s) => s.parse().map_err(serde::de::Error::custom),
                }
            }
        }
    };
}

string_serde!(Rate);
string_serde!(ByteSize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rates() {
        assert_eq!("500".parse::<Rate>().unwrap(), Rate(500));
        assert_eq!("64k".parse::<Rate>().unwrap(), Rate(64_000));
        assert_eq!("1.5MB/s".parse::<Rate>().unwrap(), Rate(1_500_000));
        assert_eq!("1 MiB/s".parse::<Rate>().unwrap(), Rate(1_048_576));
        assert_eq!("512KBps".parse::<Rate>().unwrap(), Rate(512_000));
        assert_eq!("10Mbit".parse::<Rate>().unwrap(), Rate(1_250_000));
        assert_eq!("10Mbps".parse::<Rate>().unwrap(), Rate(1_250_000));
        assert_eq!("100kbit/s".parse::<Rate>().unwrap(), Rate(12_500));
        assert_eq!("8000bps".parse::<Rate>().unwrap(), Rate(1_000));
        assert_eq!("64kb/s".parse::<Rate>().unwrap(), Rate(8_000));
    }

    #[test]
    fn parses_sizes() {
        assert_eq!("2GB".parse::<ByteSize>().unwrap(), ByteSize(2_000_000_000));
        assert_eq!("1GiB".parse::<ByteSize>().unwrap(), ByteSize(1 << 30));
        assert_eq!("500b".parse::<ByteSize>().unwrap(), ByteSize(500));
        assert!("10Mbit".parse::<ByteSize>().is_err());
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "abc", "-5MB", "5XB", "1.2.3MB"] {
            assert!(bad.parse::<Rate>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn formats() {
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_500_000), "1.50 MB");
        assert_eq!(format_bytes(999_999), "1.00 MB");
        assert_eq!(format_bytes(999_994), "999.99 kB");
        assert_eq!(Rate(2_000).to_string(), "2.00 kB/s");
    }

    #[test]
    fn serde_accepts_strings_and_ints() {
        #[derive(Deserialize)]
        struct T {
            a: Rate,
            b: Rate,
        }
        let t: T = serde_json::from_str(r#"{"a": "1MB/s", "b": 42}"#).unwrap();
        assert_eq!(t.a, Rate(1_000_000));
        assert_eq!(t.b, Rate(42));
    }
}
