pub const IV: [u64; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn right_rot(value: u64, n: u64) -> u64 {
    (value >> n) | ((value & (2_u64.pow(n as u32) - 1)) << (32 - n))
}

fn mix(a: u64, b: u64, c: u64, d: u64, m0: u64, m1: u64) -> (u64, u64, u64, u64) {
    let a = (a + b + m0) & u32::MAX as u64;
    let d = right_rot(d ^ a, 16);
    let c = (c + d) & u32::MAX as u64;
    let b = right_rot(b ^ c, 12);
    let a = (a + b + m1) & u32::MAX as u64;
    let d = right_rot(d ^ a, 8);
    let c = (c + d) & u32::MAX as u64;
    let b = right_rot(b ^ c, 7);
    (a, b, c, d)
}

fn blake_round(mut state: Vec<u64>, message: [u64; 16], sigma: [usize; 16]) -> Vec<u64> {
    (state[0], state[4], state[8], state[12]) = mix(
        state[0],
        state[4],
        state[8],
        state[12],
        message[sigma[0]],
        message[sigma[1]],
    );
    (state[1], state[5], state[9], state[13]) = mix(
        state[1],
        state[5],
        state[9],
        state[13],
        message[sigma[2]],
        message[sigma[3]],
    );
    (state[2], state[6], state[10], state[14]) = mix(
        state[2],
        state[6],
        state[10],
        state[14],
        message[sigma[4]],
        message[sigma[5]],
    );
    (state[3], state[7], state[11], state[15]) = mix(
        state[3],
        state[7],
        state[11],
        state[15],
        message[sigma[6]],
        message[sigma[7]],
    );
    (state[0], state[5], state[10], state[15]) = mix(
        state[0],
        state[5],
        state[10],
        state[15],
        message[sigma[8]],
        message[sigma[9]],
    );
    (state[1], state[6], state[11], state[12]) = mix(
        state[1],
        state[6],
        state[11],
        state[12],
        message[sigma[10]],
        message[sigma[11]],
    );
    (state[2], state[7], state[8], state[13]) = mix(
        state[2],
        state[7],
        state[8],
        state[13],
        message[sigma[12]],
        message[sigma[13]],
    );
    (state[3], state[4], state[9], state[14]) = mix(
        state[3],
        state[4],
        state[9],
        state[14],
        message[sigma[14]],
        message[sigma[15]],
    );
    state
}

pub fn blake2s_compress(
    h: [u64; 8],
    message: [u64; 16],
    t0: u64,
    t1: u64,
    f0: u64,
    f1: u64,
) -> Vec<u64> {
    let mut state = h.to_vec();
    state.extend(&IV[0..4]);
    state.extend(&vec![
        (IV[4] ^ t0),
        (IV[5] ^ t1),
        (IV[6] ^ f0),
        (IV[7] ^ f1),
    ]);
    for sigma_list in SIGMA {
        state = blake_round(state.clone(), message, sigma_list);
    }
    let mut new_state = Vec::<u64>::new();
    for i in 0..8 {
        new_state.push(h[i] ^ state[i] ^ state[8 + i]);
    }
    new_state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2s_compress_test_a() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_state: [u64; 8] = blake2s_compress(h, message, 2, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                412110711, 3234706100, 3894970767, 982912411, 937789635, 742982576, 3942558313,
                1407547065
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_b() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [45671065168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let new_state: [u64; 8] = blake2s_compress(h, message, 2, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                1350824974, 1952695342, 1124431190, 2382635687, 1038042047, 3385458632, 2704600623,
                3918286991
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_c() {
        //Hashing "Hello World"
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [
            1819043144, 1870078063, 6581362, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let new_state: [u64; 8] = blake2s_compress(h, message, 9, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                939893662, 3935214984, 1704819782, 3912812968, 4211807320, 3760278243, 674188535,
                2642110762
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_d() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [
            1819043144,
            1870078063,
            6581362,
            274628678,
            715791845926,
            17549864398,
            871587583958,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let new_state: [u64; 8] = blake2s_compress(h, message, 25, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                776892644, 2320054920, 4234376902, 197908291, 140963246, 1568612943, 2549680124,
                2702310085
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_e() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [
            1819043144,
            1870078063,
            6581362,
            274628678,
            715791845926,
            17549864398,
            871587583958,
            635963558,
            557369694645,
            1576875962,
            215769785,
            0,
            0,
            0,
            0,
            0,
        ];
        let new_state: [u64; 8] = blake2s_compress(h, message, 41, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                1991193646, 3380585732, 2874802778, 1384823757, 1773678194, 1086574221, 655848480,
                254864817
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_f() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [
            1819043144,
            1870078063,
            6581362,
            274628678,
            715791845926,
            17549864398,
            871587583958,
            635963558,
            557369694645,
            1576875962,
            215769785,
            15237957813,
            5858493030,
            7647393202,
            437383930,
            74833930,
        ];
        let new_state: [u64; 8] = blake2s_compress(h, message, 64, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                3128786092, 425343372, 1212782004, 2834037565, 110672570, 4243337238, 1946000574,
                2292116771
            ]
        )
    }

    #[test]
    fn blake2s_compress_test_g() {
        let h: [u64; 8] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225,
        ];
        let message: [u64; 16] = [
            11563522,
            43535528,
            653255322,
            274628678,
            7347194357,
            17549864398,
            871587583958,
            63593558,
            34365653565,
            1576875962,
            215769785,
            1523589257,
            583552355,
            7647393202,
            43725325930,
            748335230,
        ];
        let new_state: [u64; 8] = blake2s_compress(h, message, 64, 0, 4294967295, 0)
            .try_into()
            .unwrap();
        assert_eq!(
            new_state,
            [
                4102009366, 4180862555, 1746308258, 3582026219, 1432962757, 1520441577, 1404221369,
                2068979550
            ]
        )
    }
}
