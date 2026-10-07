//! IPv4 list parsing shared by the spoofed-IP pools and the IP tester.
//!
//! One entry per line (or separated by commas/whitespace); `#` starts a
//! comment. Every entry is one of:
//!
//! * a single address — `1.2.3.4`
//! * a CIDR block     — `1.2.3.0/24`
//! * an inclusive range — `1.2.3.10-1.2.3.40`
//!
//! Entries are stored as merged `[start, end]` ranges, so a list of thousands of
//! /24 blocks costs a few kilobytes instead of one allocation per address.

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

/// A sorted, merged set of inclusive IPv4 ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpRangeSet {
    ranges: Vec<(u32, u32)>,
    total: u64,
}

impl IpRangeSet {
    /// Parse a whole list. Errors name the offending line.
    pub fn parse(text: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("");
            for token in line.split(|c: char| c == ',' || c.is_whitespace()) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                let r = parse_entry(token)
                    .with_context(|| format!("line {}: {:?}", lineno + 1, token))?;
                ranges.push(r);
            }
        }
        Ok(Self::from_ranges(ranges))
    }

    /// Build a set from individual addresses.
    pub fn from_ips(ips: &[Ipv4Addr]) -> Self {
        Self::from_ranges(ips.iter().map(|ip| (u32::from(*ip), u32::from(*ip))).collect())
    }

    fn from_ranges(mut ranges: Vec<(u32, u32)>) -> Self {
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (s, e) in ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        let total = merged.iter().map(|(s, e)| (*e - *s) as u64 + 1).sum();
        Self { ranges: merged, total }
    }

    /// Number of individual addresses in the set.
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// O(log n) membership test.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        match self.ranges.binary_search_by(|(s, _)| s.cmp(&v)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => v <= self.ranges[i - 1].1,
        }
    }

    /// Visit every address in ascending order. The callback returns `false`
    /// to stop early.
    pub fn for_each(&self, mut f: impl FnMut(Ipv4Addr) -> bool) {
        for &(s, e) in &self.ranges {
            let mut v = s;
            loop {
                if !f(Ipv4Addr::from(v)) {
                    return;
                }
                if v == e {
                    break;
                }
                v += 1;
            }
        }
    }

    /// Expand into individual addresses, refusing sets larger than `cap`.
    pub fn expand(&self, cap: usize) -> Result<Vec<Ipv4Addr>> {
        if self.total > cap as u64 {
            bail!("IP list has {} addresses, more than the limit of {}", self.total, cap);
        }
        let mut out = Vec::with_capacity(self.total as usize);
        self.for_each(|ip| {
            out.push(ip);
            true
        });
        Ok(out)
    }
}

fn parse_entry(token: &str) -> Result<(u32, u32)> {
    if let Some((ip, bits)) = token.split_once('/') {
        let ip: Ipv4Addr = ip.trim().parse().context("bad address")?;
        let bits: u32 = bits.trim().parse().context("bad prefix length")?;
        if bits > 32 {
            bail!("prefix length must be 0-32");
        }
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let start = u32::from(ip) & mask;
        return Ok((start, start | !mask));
    }
    if let Some((a, b)) = token.split_once('-') {
        let a: Ipv4Addr = a.trim().parse().context("bad range start")?;
        let b: Ipv4Addr = b.trim().parse().context("bad range end")?;
        let (a, b) = (u32::from(a), u32::from(b));
        if a > b {
            bail!("range start is after range end");
        }
        return Ok((a, b));
    }
    let ip: Ipv4Addr = token.parse().context("bad address")?;
    Ok((u32::from(ip), u32::from(ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_single_cidr_and_range() {
        let set = IpRangeSet::parse("1.1.1.1\n10.0.0.0/30 # four\n 192.168.1.10-192.168.1.12\n").unwrap();
        assert_eq!(set.total(), 1 + 4 + 3);
        assert!(set.contains(ip("10.0.0.3")));
        assert!(!set.contains(ip("10.0.0.4")));
        assert!(set.contains(ip("192.168.1.11")));
        assert!(!set.contains(ip("1.1.1.2")));
    }

    #[test]
    fn merges_overlaps_and_duplicates() {
        let set = IpRangeSet::parse("10.0.0.0/24, 10.0.0.5\n10.0.0.250-10.0.1.3").unwrap();
        assert_eq!(set.total(), 256 + 4);
        assert_eq!(set.expand(1000).unwrap().len(), 260);
    }

    #[test]
    fn rejects_garbage_with_line_number() {
        let err = IpRangeSet::parse("1.1.1.1\nnot-an-ip").unwrap_err();
        assert!(format!("{:#}", err).contains("line 2"));
        assert!(IpRangeSet::parse("1.2.3.4/33").is_err());
        assert!(IpRangeSet::parse("1.2.3.9-1.2.3.1").is_err());
    }

    #[test]
    fn expand_respects_cap_and_edges() {
        let set = IpRangeSet::parse("255.255.255.254/31").unwrap();
        assert_eq!(set.expand(2).unwrap(), vec![ip("255.255.255.254"), ip("255.255.255.255")]);
        assert!(IpRangeSet::parse("10.0.0.0/16").unwrap().expand(100).is_err());
    }
}
