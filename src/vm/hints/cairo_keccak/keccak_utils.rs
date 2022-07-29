use num_integer::Integer;
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub enum KeccakError {
    PrecomputeRhoOffsetsError(usize, usize),
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
) -> Result<Vec<usize>, KeccakError> {
    /*
    Precomputes the offsets of the rotation in the Rho phase.
    Returns a matrix with the rotation offset of each lane.
     */
    let (mut x, mut y) = (1, 0);
    let mut xy_pairs = HashSet::new();
    let mut offset = 0;
    let mut result = vec![0; (u as usize).pow(2)];

    for t in 0..u.pow(2) {
        xy_pairs.insert((x, y));
        offset = (offset + t).mod_floor(&w);
        result[u * y + x] = offset;
        // The official definition is (alpha, beta) = (3, 2) for u = 5. Any other u has no official
        // definition, but the iteration must go over each (x, y) != (0, 0) pair exactly once.
        (x, y) = (y, (beta * x + alpha * y).mod_floor(&u));
    }
    if xy_pairs.len() != u.pow(2) {
        return Err(KeccakError::PrecomputeRhoOffsetsError(
            xy_pairs.len(),
            u.pow(2),
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompute_rho_offsets_test() {
        let res = precompute_rho_offsets(2, 2, 3, 3);
        assert_eq!(res, Ok(vec![0, 1, 1, 0]));
    }
}
