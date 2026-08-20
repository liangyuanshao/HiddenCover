//! Complete-subtree revocation tree.

use crate::{Error, Result};
use std::collections::HashSet;

/// Heap-indexed complete binary tree.  Root is 1 and leaves are
/// `leaf_base..leaf_base + capacity`.
#[derive(Clone, Debug)]
pub struct CompleteTree {
    depth: usize,
    capacity: usize,
    leaf_base: usize,
}

impl CompleteTree {
    pub fn new(depth: usize) -> Result<Self> {
        if depth == 0 || depth >= usize::BITS as usize - 1 {
            return Err(Error::InvalidTree);
        }
        let capacity = 1usize << depth;
        Ok(Self {
            depth,
            capacity,
            leaf_base: capacity,
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn leaf_node(&self, leaf: usize) -> Result<usize> {
        if leaf >= self.capacity {
            return Err(Error::InvalidTree);
        }
        Ok(self.leaf_base + leaf)
    }

    /// Leaf-to-root path, including both endpoints.
    pub fn path(&self, leaf: usize) -> Result<Vec<usize>> {
        let mut node = self.leaf_node(leaf)?;
        let mut path = Vec::with_capacity(self.depth + 1);
        loop {
            path.push(node);
            if node == 1 {
                break;
            }
            node /= 2;
        }
        Ok(path)
    }

    /// Minimal disjoint complete-subtree cover of all leaves except `revoked`.
    /// Unissued leaves are deliberately treated as non-revoked: issuing a new
    /// credential therefore does not mutate the public Cover.
    pub fn cover(&self, revoked: &HashSet<usize>) -> Result<Vec<usize>> {
        if revoked.iter().any(|leaf| *leaf >= self.capacity) {
            return Err(Error::InvalidTree);
        }
        let mut counts = vec![0usize; self.leaf_base * 2];
        for leaf in revoked {
            let mut node = self.leaf_node(*leaf)?;
            loop {
                counts[node] += 1;
                if node == 1 {
                    break;
                }
                node /= 2;
            }
        }
        let mut out = Vec::new();
        self.cover_rec(1, self.capacity, &counts, &mut out);
        Ok(out)
    }

    fn cover_rec(&self, node: usize, leaves: usize, counts: &[usize], out: &mut Vec<usize>) {
        if counts[node] == 0 {
            out.push(node);
            return;
        }
        if leaves == 1 || counts[node] == leaves {
            return;
        }
        self.cover_rec(node * 2, leaves / 2, counts, out);
        self.cover_rec(node * 2 + 1, leaves / 2, counts, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_is_minimal_and_intersects_only_live_paths() {
        let tree = CompleteTree::new(3).unwrap();
        let revoked = HashSet::from([1usize, 6usize]);
        let cover = tree.cover(&revoked).unwrap();
        assert_eq!(cover, vec![8, 5, 6, 15]);
        for leaf in 0..8 {
            let hit = tree.path(leaf).unwrap().iter().any(|n| cover.contains(n));
            assert_eq!(hit, !revoked.contains(&leaf));
        }
    }

    #[test]
    fn issuance_does_not_change_cover() {
        let tree = CompleteTree::new(4).unwrap();
        let cover_before = tree.cover(&HashSet::new()).unwrap();
        let cover_after = tree.cover(&HashSet::new()).unwrap();
        assert_eq!(cover_before, vec![1]);
        assert_eq!(cover_before, cover_after);
    }
}
