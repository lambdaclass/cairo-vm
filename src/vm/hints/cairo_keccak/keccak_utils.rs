use crate::bigint;
use crate::bigint_u128;
use crate::bigintusize;
use num_bigint::{BigInt, Sign};
use num_integer::div_ceil;
use num_integer::Integer;
use num_traits::FromPrimitive;
use std::collections::HashSet;
use std::ops::Shl;

#[derive(Debug, PartialEq)]
pub enum KeccakError {
    PrecomputeRhoOffsetsError(usize, usize),
    PrecomputeRcError(usize),
    MessageLenError(usize, usize),
    BigIntMaxSize(BigInt),
}

pub fn rot_left(x: &BigInt, n: usize, w: usize) -> BigInt {
    /*
    Rotates a w-bit number n bits to the left.
    */
    ((x << n) & (bigint!(1).shl(w) - 1_i32)) | (x >> (w - n))
}

pub fn precompute_rho_offsets(
    w: usize,
    u: usize,
    alpha: usize,
    beta: usize,
) -> Result<Vec<Vec<usize>>, KeccakError> {
    /*
    Precomputes the offsets of the rotation in the Rho phase.
    Returns a matrix with the rotation offset of each lane.
     */
    let m = u.pow(2);
    let (mut x, mut y) = (1, 0);
    let mut xy_pairs = HashSet::new();
    let mut offset = 0;
    let mut result = vec![vec![0; u]; u];

    for t in 1..m {
        xy_pairs.insert((x, y));
        offset = (offset + t).mod_floor(&w);
        result[x][y] = offset;
        // The official definition is (alpha, beta) = (3, 2) for u = 5. Any other u has no official
        // definition, but the iteration must go over each (x, y) != (0, 0) pair exactly once.
        (x, y) = (y, (beta * x + alpha * y).mod_floor(&u));
    }

    if xy_pairs.len() != u.pow(2) - 1 {
        return Err(KeccakError::PrecomputeRhoOffsetsError(xy_pairs.len(), m));
    }

    Ok(result)
}

pub fn precompute_rc(ell: usize, mut rounds: Option<usize>) -> Result<Vec<BigInt>, KeccakError> {
    /*
    Precomputes the round constants in the Iota phase.
    Returns a sequence of keys to be xored in each round to lane [0, 0].
    */
    let mut x = 1;

    if let None = rounds {
        rounds = Some(12 + 2 * ell);
    }

    let mut rc = Vec::new();

    // safe to unwrap here since `rounds` can't be None
    for _ in 0..rounds.unwrap() {
        let mut rc_elem = 0;

        for m in 0_usize..(ell + 1) {
            let temp0: usize = x & 1;

            let temp1: usize = 2_usize.pow(
                m.try_into()
                    .map_err(|_| KeccakError::PrecomputeRcError(m))?,
            ) - 1;

            rc_elem += temp0 << temp1;

            x <<= 1;
            x ^= 0x171 * (x >> 8);
        }

        rc.push(bigintusize!(rc_elem));
    }

    Ok(rc)
}

pub fn keccak_round(
    a: Vec<Vec<BigInt>>,
    rho_offsets: &Vec<Vec<usize>>,
    rc: BigInt,
    w: usize,
    u: usize,
    alpha: usize,
    beta: usize,
) -> Vec<Vec<BigInt>> {
    /*
    Performs one keccak round on a matrix of uxu w-bit integers.
    rc is the round constant.
    */
    let mut b = Vec::new();
    let mut c = Vec::new();
    let mut d = Vec::new();
    let mut a_tmp = Vec::new();

    for x in 0..u {
        let c_elem = a[x].iter().fold(bigint!(0), |acc, n| acc ^ n);
        c.push(c_elem);
    }

    for x in 0..u {
        let left_xor = &c[(x as i32 - 1).mod_floor(&(u as i32)) as usize];
        let right_xor = rot_left(&c[(x + 1).mod_floor(&u)], 1, w);
        let d_elem = left_xor ^ right_xor;

        d.push(d_elem);
    }

    for x in 0..u {
        let mut a_tmp_elem = Vec::new();
        for y in 0..u {
            a_tmp_elem.push(&a[x][y] ^ &d[x]);
        }
        a_tmp.push(a_tmp_elem);
    }

    for x in 0..u {
        b.push(a_tmp[x].clone());
    }

    for x in 0..u {
        for y in 0..u {
            b[y][(beta * x + alpha * y).mod_floor(&u)] =
                rot_left(&a_tmp[x][y], rho_offsets[x][y], w);
        }
    }

    for x in 0..u {
        for y in 0..u {
            a_tmp[x][y] =
                &b[x][y] ^ ((!&b[(x + 1).mod_floor(&u)][y]) & &b[(x + 2).mod_floor(&u)][y]);
        }
    }

    a_tmp[0][0] ^= rc;

    a_tmp
}

fn keccak_func(
    values: Vec<BigInt>,
    ell: u32,
    u: usize,
    alpha: usize,
    beta: usize,
    rounds: Option<usize>,
) -> Result<Vec<BigInt>, KeccakError> {
    /*
    Computes the keccak block permutation on u**2 2**ell-bit integers.
    */
    // Reshape values to a matrix
    let mut value_matrix = Vec::new();

    for x in 0..u {
        let mut row = Vec::new();
        for y in 0..u {
            row.push(values[u * y + x].clone())
        }
        value_matrix.push(row);
    }

    let w = 2_usize.pow(ell);

    let rho_offsets = precompute_rho_offsets(w, u, alpha, beta)?;

    for rc in precompute_rc(ell as usize, rounds)?.iter() {
        value_matrix = keccak_round(value_matrix, &rho_offsets, rc.clone(), w, u, alpha, beta);
    }

    let mut values_res = Vec::new();
    for x in 0..u {
        for y in 0..u {
            values_res.push(value_matrix[y][x].clone());
        }
    }

    Ok(values_res)
}

#[allow(dead_code)]
fn keccak_f(
    message: Vec<u8>,
    ell: usize,
    u: usize,
    alpha: u32,
    beta: u32,
    rounds: Option<usize>,
) -> Result<Vec<u8>, KeccakError> {
    /*
    Computes the keccak block permutation on a u**2*2**ell-bit message (pads with zeros).
    */
    let w = 2_usize.pow(ell as u32);

    if message.len() > div_ceil(u * u * w, 8) {
        return Err(KeccakError::MessageLenError(
            message.len(),
            div_ceil(u * u * w, 8),
        ));
    }

    let as_bigint: BigInt = BigInt::from_bytes_le(Sign::Plus, &message);

    //if as_bigint >= bigint_u128!(2_u128.pow((u * u * w))) {
    if as_bigint >= bigint!(1).shl(u * u * w) {
        return Err(KeccakError::BigIntMaxSize(as_bigint));
    }

    let mut as_integers = Vec::new();
    for i in 0..(u * u) {
        let integer = (as_bigint.clone() >> (i * w)) & (bigint_u128!(2_u128.pow(w as u32) - 1));
        as_integers.push(integer);
    }

    let result = keccak_func(
        as_integers,
        ell as u32,
        u,
        alpha as usize,
        beta as usize,
        rounds,
    )?;

    let mut sum_vec = Vec::new();
    for (i, x) in result.iter().enumerate() {
        let s: BigInt = x << (i * w);
        sum_vec.push(s);
    }

    let sum = sum_vec
        .iter()
        .fold(bigint!(0), |acc: BigInt, x: &BigInt| acc + x);

    let (_, mut bytes) = sum.to_bytes_le();
    bytes.resize((u.pow(2_u32) * w + 7) / 8, 0);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint_u64;

    #[test]
    fn rot_left_test() {
        let res = rot_left(&bigint!(5), 2, 32);

        assert_eq!(res, bigint!(20));
    }

    #[test]
    fn precompute_rho_offsets_test() {
        let res = precompute_rho_offsets(2, 5, 3, 2);
        // Python version result: [[0, 0, 1, 1, 0], [1, 0, 0, 1, 0], [0, 0, 1, 1, 1], [0, 1, 1, 1, 0], [1, 0, 1, 0, 0]]
        assert_eq!(
            res,
            Ok(vec![
                vec![0, 0, 1, 1, 0],
                vec![1, 0, 0, 1, 0],
                vec![0, 0, 1, 1, 1],
                vec![0, 1, 1, 1, 0],
                vec![1, 0, 1, 0, 0]
            ])
        );
    }

    #[test]
    fn precompute_rc_test() {
        let ell = 5;
        let rounds = None;

        let res = precompute_rc(ell, rounds);

        assert_eq!(
            res,
            Ok(vec![
                bigint_u64!(1),
                bigint_u64!(2147516424),
                bigint_u64!(2147516544),
                bigint_u64!(9),
                bigint_u64!(2147516554),
                bigint_u64!(2147483659),
                bigint_u64!(32768),
                bigint_u64!(2147516545),
                bigint_u64!(2147483779),
                bigint_u64!(2147516546),
                bigint_u64!(2147483648),
                bigint_u64!(32769),
                bigint_u64!(137),
                bigint_u64!(32771),
                bigint_u64!(2147516555),
                bigint_u64!(32906),
                bigint_u64!(2147516426),
                bigint_u64!(32905),
                bigint_u64!(2147483778),
                bigint_u64!(32776),
                bigint_u64!(2147483656),
                bigint_u64!(32778)
            ])
        );
    }

    #[test]
    fn keccak_round_test() {
        let a = vec![
            vec![bigint!(1), bigint!(2), bigint!(3)],
            vec![bigint!(4), bigint!(5), bigint!(6)],
            vec![bigint!(6), bigint!(7), bigint!(8)],
        ];
        let rho_offsets = vec![vec![1, 2, 3], vec![4, 5, 6], vec![6, 7, 8]];
        let rc = bigint!(2);
        let w = 32;
        let u = 2;
        let alpha = 3;
        let beta = 3;

        let res = keccak_round(a, &rho_offsets, rc, w, u, alpha, beta);

        // Python version result: [[2, 0], [0, 0]]
        assert_eq!(
            res,
            vec![vec![bigint!(2), bigint!(0)], vec![bigint!(0), bigint!(0)]]
        );
    }

    #[test]
    fn keccak_func_test() {
        let values = vec![bigint!(0); 25];
        let ell = 6;
        let u = 5;
        let alpha = 3;
        let beta = 2;
        let rounds = None;

        let res = keccak_func(values, ell, u, alpha, beta, rounds);

        assert_eq!(
            res,
            Ok(vec![
                bigint_u64!(17376452488221285863),
                bigint_u64!(9571781953733019530),
                bigint_u64!(15391093639620504046),
                bigint_u64!(13624874521033984333),
                bigint_u64!(10027350355371872343),
                bigint_u64!(18417369716475457492),
                bigint_u64!(10448040663659726788),
                bigint_u64!(10113917136857017974),
                bigint_u64!(12479658147685402012),
                bigint_u64!(3500241080921619556),
                bigint_u64!(16959053435453822517),
                bigint_u64!(12224711289652453635),
                bigint_u64!(9342009439668884831),
                bigint_u64!(4879704952849025062),
                bigint_u64!(140226327413610143),
                bigint_u64!(424854978622500449),
                bigint_u64!(7259519967065370866),
                bigint_u64!(7004910057750291985),
                bigint_u64!(13293599522548616907),
                bigint_u64!(10105770293752443592),
                bigint_u64!(10668034807192757780),
                bigint_u64!(1747952066141424100),
                bigint_u64!(1654286879329379778),
                bigint_u64!(8500057116360352059),
                bigint_u64!(16929593379567477321)
            ])
        )
    }

    #[test]
    fn keccak_f_test() {
        let message = vec![0, 2];
        let ell = 6;
        let u = 5;
        let alpha = 3;
        let beta = 2;
        let rounds = None;

        let res = keccak_f(message, ell, u, alpha, beta, rounds);

        assert_eq!(
            res,
            Ok(vec![
                123, 140, 119, 20, 139, 152, 191, 39, 45, 173, 27, 129, 20, 139, 24, 125, 139, 64,
                131, 63, 0, 165, 160, 208, 176, 236, 47, 193, 187, 111, 250, 0, 148, 141, 71, 215,
                123, 234, 249, 47, 194, 73, 14, 218, 230, 126, 177, 205, 125, 173, 118, 215, 103,
                21, 124, 251, 178, 219, 62, 130, 35, 154, 115, 224, 150, 34, 195, 146, 9, 39, 114,
                23, 131, 39, 126, 135, 96, 64, 4, 149, 192, 221, 102, 67, 58, 30, 218, 191, 209,
                67, 161, 70, 129, 164, 217, 131, 209, 183, 223, 32, 137, 176, 181, 225, 64, 129,
                50, 56, 127, 185, 88, 89, 182, 92, 252, 206, 103, 39, 245, 62, 40, 141, 111, 140,
                11, 16, 30, 123, 14, 198, 226, 241, 143, 26, 225, 169, 34, 82, 204, 237, 73, 1, 15,
                79, 179, 224, 109, 60, 78, 245, 74, 24, 45, 158, 96, 214, 120, 203, 9, 160, 86,
                112, 203, 230, 207, 39, 255, 19, 78, 252, 233, 1, 118, 248, 251, 129, 124, 236, 74,
                182, 151, 186, 123, 209, 243, 184, 107, 32, 208, 52, 5, 244, 235, 35, 166, 254, 52,
                98, 86, 11
            ])
        )
    }
}
