// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{self, LengthPolicy};

use super::{ContainerError, ContainerErrorReason as Reason};
use crate::cbor_boundary;

/// Borrowed spans avoid partially allocated sensitive decoder trees entirely.
#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    pub encoded: &'a [u8],
    pub data: &'a [u8],
    pub major: u8,
    pub argument: u64,
}

impl<'a> Item<'a> {
    pub(super) fn integer(self) -> Result<i64, ContainerError> {
        let n = i64::try_from(self.argument).map_err(|_| Reason::Malformed)?;
        match self.major {
            0 => Ok(n),
            1 => n
                .checked_neg()
                .and_then(|negative| negative.checked_sub(1))
                .ok_or(Reason::Malformed.into()),
            _ => Err(Reason::Malformed.into()),
        }
    }

    pub(super) fn bytes(self) -> Result<&'a [u8], ContainerError> {
        if self.major != 2 {
            return Err(Reason::Malformed.into());
        }
        Ok(self.data)
    }

    pub(super) fn count(self, major: u8) -> Result<usize, ContainerError> {
        if self.major != major {
            return Err(Reason::Malformed.into());
        }
        usize::try_from(self.argument).map_err(|_| Reason::Limit.into())
    }

    pub(super) fn cursor(self) -> Result<Cursor<'a>, ContainerError> {
        Ok(Cursor {
            shared: general::Cursor::new(
                self.data,
                cbor_boundary::limits()?,
                LengthPolicy::DefiniteOnly,
            )
            .map_err(cbor_boundary::error)?,
        })
    }

    pub(super) fn from_validated(encoded: &'a [u8]) -> Result<Self, ContainerError> {
        let frame = general::frame_exact(
            encoded,
            cbor_boundary::limits()?,
            LengthPolicy::DefiniteOnly,
        )
        .map_err(cbor_boundary::error)?;
        Self::from_frame(frame)
    }

    fn from_frame(frame: general::Frame<'a>) -> Result<Self, ContainerError> {
        let header = frame.header();
        let encoded = frame.received_bytes();
        let argument = if let Some(argument) = header.argument() {
            argument
        } else {
            header
                .float()
                .map_err(cbor_boundary::error)?
                .ok_or(Reason::Malformed)?
                .bits()
        };
        Ok(Self {
            data: encoded
                .get(header.received_bytes().len()..)
                .ok_or(Reason::Malformed)?,
            encoded,
            major: cbor_boundary::major_code(header.major_type())?,
            argument,
        })
    }
}

pub(super) struct Cursor<'a> {
    shared: general::Cursor<'a>,
}

impl<'a> Cursor<'a> {
    // Successful preflight and traversal share codec's framing implementation.
    // The cursor keeps cumulative work and node limits across all children.
    pub(super) fn next(&mut self) -> Result<Item<'a>, ContainerError> {
        let frame = self
            .shared
            .next()
            .ok_or(Reason::Malformed)?
            .map_err(cbor_boundary::error)?;
        Item::from_frame(frame)
    }
}
