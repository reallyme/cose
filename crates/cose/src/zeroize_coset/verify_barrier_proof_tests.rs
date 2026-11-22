// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroize;

// The barrier observes memory to prevent compiler elimination; it does not
// change values. Kani cannot execute its assembly. Model only that observation,
// retaining the preceding volatile erasure writes in every affected harness.
// This model cannot establish resistance to compiler optimization.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
pub(crate) fn observe_barrier<T: ?Sized>(_value: &T) {}

#[kani::proof]
#[kani::unwind(5)]
#[kani::stub(zeroize::optimization_barrier, observe_barrier)]
fn zeroize_retains_volatile_erasure_with_the_barrier_model() {
    let original: [u8; 4] = kani::any();
    let mut fixed = original;
    fixed.zeroize();
    assert!(fixed == [0; 4]);

    let mut sliced = original;
    sliced.as_mut_slice().zeroize();
    assert!(sliced == [0; 4]);

    kani::cover!(original != [0; 4], "nonzero bytes are erased");
    kani::cover!(original == [0; 4], "zero bytes remain erased");
}
