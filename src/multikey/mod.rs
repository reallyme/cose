// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE_Key and Multikey conversion helpers.

mod convert;

pub use convert::{cose_key_to_multikey, multikey_to_cose_key};
