#![cfg_attr(not(test), no_std)]

pub const DSCP_ID_MAX: u8 = 63;

pub const IPV4_TOS_OFFSET: usize = 1;
pub const IPV4_CHECK_OFFSET: usize = 10;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const CTR_TAGGED: u32 = 0;
pub const CTR_UNTAGGED: u32 = 1;
pub const COUNTER_SLOTS: u32 = 2;

pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!check) as u32 + (!old) as u32 + new as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

pub fn tos_with_dscp(tos: u8, dscp: u8) -> u8 {
    (dscp << 2) | (tos & 0x03)
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ArpKey {
    pub ifindex: u32,
    pub ip: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct FlowKey {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

impl FlowKey {
    pub fn new(src: u32, dst: u32, sport: u16, dport: u16, proto: u8) -> Self {
        Self {
            src,
            dst,
            sport,
            dport,
            proto,
            _pad: [0; 3],
        }
    }

    pub fn reversed(&self) -> Self {
        Self::new(self.dst, self.src, self.dport, self.sport, self.proto)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_checksum(header: &[u8; 20]) -> u16 {
        let mut sum = 0u32;
        for word in header.chunks(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn sample_header(tos: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[1] = tos;
        h[2..4].copy_from_slice(&1500u16.to_be_bytes());
        h[4..6].copy_from_slice(&0xabcdu16.to_be_bytes());
        h[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        h[8] = 64;
        h[9] = IPPROTO_TCP;
        h[10..12].copy_from_slice(&[0, 0]);
        h[12..16].copy_from_slice(&[203, 0, 113, 7]);
        h[16..20].copy_from_slice(&[110, 110, 110, 110]);
        let c = full_checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h
    }

    #[test]
    fn incremental_checksum_matches_full_recompute() {
        for old_dscp in 0u8..64 {
            for new_dscp in 0u8..64 {
                let old_tos = old_dscp << 2;
                let new_tos = new_dscp << 2;

                let old_header = sample_header(old_tos);
                let stored = u16::from_be_bytes([old_header[10], old_header[11]]);

                let old_word = ((old_header[0] as u16) << 8) | old_tos as u16;
                let new_word = ((old_header[0] as u16) << 8) | new_tos as u16;
                let incremental = csum_replace2(stored, old_word, new_word);

                let mut expected_header = old_header;
                expected_header[1] = new_tos;
                expected_header[10..12].copy_from_slice(&[0, 0]);
                let expected = full_checksum(&expected_header);

                assert_eq!(
                    incremental, expected,
                    "dscp {old_dscp} -> {new_dscp} produced a wrong checksum"
                );
            }
        }
    }

    #[test]
    fn incremental_checksum_preserves_ecn_bits() {
        for ecn in 0u8..4 {
            let old_tos = (7 << 2) | ecn;
            let new_tos = tos_with_dscp(old_tos, 0);
            assert_eq!(new_tos & 0x03, ecn);

            let header = sample_header(old_tos);
            let stored = u16::from_be_bytes([header[10], header[11]]);
            let old_word = ((header[0] as u16) << 8) | old_tos as u16;
            let new_word = ((header[0] as u16) << 8) | new_tos as u16;

            let mut expected_header = header;
            expected_header[1] = new_tos;
            expected_header[10..12].copy_from_slice(&[0, 0]);

            assert_eq!(
                csum_replace2(stored, old_word, new_word),
                full_checksum(&expected_header)
            );
        }
    }

    #[test]
    fn tos_with_dscp_replaces_only_the_dscp_bits() {
        assert_eq!(tos_with_dscp(0b1111_1111, 0), 0b0000_0011);
        assert_eq!(tos_with_dscp(0b0000_0010, 63), 0b1111_1110);
        assert_eq!(tos_with_dscp(0, 7), 7 << 2);
    }

    #[test]
    fn flow_key_reversed_is_an_involution() {
        let key = FlowKey::new(0x0a00_0001, 0x0a00_0002, 1234, 80, IPPROTO_TCP);
        let back = key.reversed().reversed();
        assert_eq!(key, back);
        assert_eq!(key.reversed().src, key.dst);
        assert_eq!(key.reversed().sport, key.dport);
    }

    #[test]
    fn flow_key_padding_is_always_zeroed() {
        let key = FlowKey::new(1, 2, 3, 4, IPPROTO_UDP);
        assert_eq!(key._pad, [0; 3]);
        assert_eq!(key.reversed()._pad, [0; 3]);
    }
}
