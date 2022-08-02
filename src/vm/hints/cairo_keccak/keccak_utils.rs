use crate::bigint;
use crate::bigint_u128;
use crate::bigintusize;
use num_bigint::{BigInt, Sign};
use num_integer::div_ceil;
use num_integer::Integer;
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashSet;
use std::ops::Shl;

#[derive(Debug, PartialEq)]
pub enum KeccakError {
    PrecomputeRhoOffsetsError(usize, usize),
    PrecomputeRcError(usize),
    MessageLenError(usize, usize),
    BigIntMaxSize(BigInt),
}

/*

def rot_left(x, n, w):
    """
    Rotates a w-bit number n bits to the left.
    """
    return ((x << n) & (2**w - 1)) | (x >> (w - n))

*/
pub fn rot_left(x: usize, n: usize, w: usize) -> usize {
    /*
    Rotates a w-bit number n bits to the left.
    */
    ((x << n) & (2_u128).pow(w as u32 - 1) as usize) | (x >> (w - n))
}

/*

def precompute_rho_offsets(w: int, u: int, alpha: int, beta: int) -> List[List[int]]:
    """
    Precomputes the offsets of the rotation in the Rho phase.
    Returns a matrix with the rotation offset of each lane.
    """
    x, y = 1, 0
    xy_pairs = set()
    offset = 0
    result = [[0] * u for _ in range(u)]
    for t in range(1, u**2):
        xy_pairs.add((x, y))
        offset = (offset + t) % w
        result[x][y] = offset
        # The official definition is (alpha, beta) = (3, 2) for u = 5. Any other u has no official
        # definition, but the iteration must go over each (x, y) != (0, 0) pair exactly once.
        x, y = y, (beta * x + alpha * y) % u
    assert len(xy_pairs) == u**2 - 1
    return result

*/
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

/*
def precompute_rc(ell: int, rounds: Optional[int] = None) -> Iterable[int]:
    """
    Precomputes the round constants in the Iota phase.
    Returns a sequence of keys to be xored in each round to lane [0, 0].
    """
    x = 1
    if rounds is None:
        rounds = 12 + 2 * ell
    for _ in range(rounds):
        rc = 0
        for m in range(ell + 1):
            rc += (x & 1) << (2**m - 1)
            x <<= 1
            x ^= 0x171 * (x >> 8)
        yield rc
*/
pub fn precompute_rc(ell: usize, mut rounds: Option<usize>) -> Result<Vec<usize>, KeccakError> {
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

        rc.push(rc_elem);
    }

    Ok(rc)
}

/*

def keccak_round(
    a: List[List[int]], rho_offsets: List[List[int]], rc: int, w: int, u: int, alpha: int, beta: int
) -> List[List[int]]:
    """
    Performs one keccak round on a matrix of uxu w-bit integers.
    rc is the round constant.
    """
    c = [reduce(operator.xor, a[x]) for x in range(u)]
    print("C: ", c)
    d = [c[(x - 1) % u] ^ rot_left(c[(x + 1) % u], 1, w) for x in range(u)]
    print("D: ", d)
    a = [[a[x][y] ^ d[x] for y in range(u)] for x in range(u)]
    print("A: ", a)
    b = [a[x][:] for x in range(u)]
    print("B: ", b)
    for x in range(u):
        for y in range(u):
            b[y][(beta * x + alpha * y) % u] = rot_left(a[x][y], rho_offsets[x][y], w)
    a = [[b[x][y] ^ ((~b[(x + 1) % u][y]) & b[(x + 2) % u][y]) for y in range(u)] for x in range(u)]
    a[0][0] ^= rc
    return a

 */
pub fn keccak_round(
    a: Vec<Vec<usize>>,
    rho_offsets: &Vec<Vec<usize>>,
    rc: usize,
    w: usize,
    u: usize,
    alpha: usize,
    beta: usize,
) -> Vec<Vec<usize>> {
    /*
    Performs one keccak round on a matrix of uxu w-bit integers.
    rc is the round constant.
    */
    let mut b: Vec<Vec<usize>> = Vec::new();
    let mut c = Vec::new();
    let mut d: Vec<usize> = Vec::new();
    let mut a_tmp: Vec<Vec<usize>> = Vec::new();

    for x in 0..u {
        let c_elem = a[x].iter().fold(0, |acc, n| acc ^ *n);
        c.push(c_elem);
    }

    for x in 0..u {
        // FIXME casts
        let foo = rot_left(c[(x + 1).mod_floor(&u)], 1, w);

        let d_elem = c[(x as i32 - 1).mod_floor(&(u as i32)) as usize] ^ foo;
        d.push(d_elem);
    }

    for x in 0..u {
        let mut a_tmp_elem = Vec::new();
        for y in 0..u {
            a_tmp_elem.push(a[x][y] ^ d[x]);
        }
        a_tmp.push(a_tmp_elem);
    }

    for x in 0..u {
        // FIXME clone
        b.push(a_tmp[x].clone());
    }

    for x in 0..u {
        for y in 0..u {
            b[y][(beta * x + alpha * y).mod_floor(&u)] =
                rot_left(a_tmp[x][y], rho_offsets[x][y], w);
        }
    }

    let mut a_new: Vec<Vec<usize>> = Vec::new();
    for x in 0..u {
        let mut a_new_tmp = Vec::new();
        for y in 0..u {
            let a_new_tmp_elem =
                b[x][y] ^ ((!b[(x + 1).mod_floor(&u)][y]) & b[(x + 2).mod_floor(&u)][y]);
            a_new_tmp.push(a_new_tmp_elem);
        }
        a_new.push(a_new_tmp);
    }

    a_new[0][0] ^= rc;

    a_new
}

/*

def keccak_func(
    values: List[int],
    ell: int = 6,
    u: int = 5,
    alpha: int = 3,
    beta: int = 2,
    rounds: Optional[int] = None,
) -> List[int]:
    """
    Computes the keccak block permutation on u**2 2**ell-bit integers.
    """
    # Reshape values to a matrix.
    value_matrix = [[values[u * y + x] for y in range(u)] for x in range(u)]
    w = 2**ell
    rho_offsets = precompute_rho_offsets(w, u, alpha, beta)
    for rc in precompute_rc(ell, rounds):
        value_matrix = keccak_round(a=value_matrix, rho_offsets=rho_offsets, rc=rc, w=w, u=u, alpha=alpha, beta=beta)
    # Reshape values to a flat list.
    values = [value_matrix[y][x] for x in range(u) for y in range(u)]

    return values

*/
fn keccak_func(
    values: Vec<usize>,
    ell: u32,
    u: usize,
    alpha: usize,
    beta: usize,
    rounds: Option<usize>,
) -> Result<Vec<usize>, KeccakError> {
    /*
    Computes the keccak block permutation on u**2 2**ell-bit integers.
    */
    // Reshape values to a matrix
    let mut value_matrix: Vec<Vec<usize>> = Vec::new();

    for x in 0..u {
        let mut row: Vec<usize> = Vec::new();
        for y in 0..u {
            row.push(values[u * y + x])
        }
        value_matrix.push(row);
    }

    let w = 2_usize.pow(ell);

    let rho_offsets = precompute_rho_offsets(w, u, alpha, beta)?;

    // el error tiene que estar acá
    for rc in precompute_rc(ell as usize, rounds)?.iter() {
        value_matrix = keccak_round(value_matrix, &rho_offsets, *rc, w, u, alpha, beta);
        //println!("value_matrix2: {:?}", value_matrix);
    }

    let mut values_res: Vec<usize> = Vec::new();
    for x in 0..u {
        for y in 0..u {
            values_res.push(value_matrix[y][x]);
        }
    }

    Ok(values_res)
}

/*

def keccak_f(
    message: bytes,
    ell: int = 6,
    u: int = 5,
    alpha: int = 3,
    beta: int = 2,
    rounds: Optional[int] = None,
) -> bytes:
    """
    Computes the keccak block permutation on a u**2*2**ell-bit message (pads with zeros).
    """
    w = 2**ell
    assert len(message) <= div_ceil(u * u * w, 8)
    as_bigint = from_bytes(message, byte_order="little")
    assert as_bigint < 2 ** (u * u * w)
    as_integers = [(as_bigint >> (i * w)) & (2**w - 1) for i in range(u**2)]
    result = keccak_func(values=as_integers, ell=ell, u=u, alpha=alpha, beta=beta, rounds=rounds)
    return to_bytes(
        sum(x << (i * w) for i, x in enumerate(result)),
        length=(u**2 * w + 7) // 8,
        byte_order="little",
    )

*/
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

    let mut as_integers: Vec<usize> = Vec::new();
    for i in 0..(u * u) {
        // FIXME unwrap
        let integer = ((as_bigint.clone() >> (i * w)) & (bigint_u128!(2_u128.pow(w as u32) - 1)))
            .to_usize()
            .unwrap();
        as_integers.push(integer);
    }

    let result: Vec<BigInt> = keccak_func(
        as_integers,
        ell as u32,
        u,
        alpha as usize,
        beta as usize,
        rounds,
    )?
    .iter()
    .map(|n| bigintusize!(*n))
    .collect();

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

    #[test]
    fn rot_left_test() {
        let res = rot_left(5, 2, 32);

        assert_eq!(res, 20);
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
                1, 2147516424, 2147516544, 9, 2147516554, 2147483659, 32768, 2147516545,
                2147483779, 2147516546, 2147483648, 32769, 137, 32771, 2147516555, 32906,
                2147516426, 32905, 2147483778, 32776, 2147483656, 32778
            ])
        );
    }

    #[test]
    fn keccak_round_test() {
        let a = vec![vec![1, 2, 3], vec![4, 5, 6], vec![6, 7, 8]];
        let rho_offsets = vec![vec![1, 2, 3], vec![4, 5, 6], vec![6, 7, 8]];
        let rc = 2;
        let w = 32;
        let u = 2;
        let alpha = 3;
        let beta = 3;

        let res = keccak_round(a, &rho_offsets, rc, w, u, alpha, beta);

        // Python version result: [[2, 0], [0, 0]]
        assert_eq!(res, vec![vec![2, 0], vec![0, 0]]);
    }

    #[test]
    fn keccak_func_test() {
        let values = vec![0; 25];
        let ell = 6;
        let u = 5;
        let alpha = 3;
        let beta = 2;
        let rounds = None;

        let res = keccak_func(values, ell, u, alpha, beta, rounds);

        assert_eq!(
            res,
            Ok(vec![
                17376452488221285863,
                9571781953733019530,
                15391093639620504046,
                13624874521033984333,
                10027350355371872343,
                18417369716475457492,
                10448040663659726788,
                10113917136857017974,
                12479658147685402012,
                3500241080921619556,
                16959053435453822517,
                12224711289652453635,
                9342009439668884831,
                4879704952849025062,
                140226327413610143,
                424854978622500449,
                7259519967065370866,
                7004910057750291985,
                13293599522548616907,
                10105770293752443592,
                10668034807192757780,
                1747952066141424100,
                1654286879329379778,
                8500057116360352059,
                16929593379567477321
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
