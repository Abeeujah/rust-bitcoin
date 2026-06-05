// SPDX-License-Identifier: CC0-1.0

//! Tests for the async poll-based encode/decode drivers.
//!
//! These tests use a hand-rolled no-op waker and a trivial `block_on`.

use core::convert::Infallible;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use bitcoin_consensus_encoding::{
    decode_from_async_read_unbuffered, decode_from_async_read_with_buffer, drain_to_async_writer,
    encode_to_async_writer, ArrayDecoder, ArrayEncoder, AsyncReadError, AsyncWriteError, Decode,
    Decoder, DecoderStatus, Encode, UnexpectedEofError,
};

// no-op waker + minimal block_on

fn noop_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

fn noop_waker() -> Waker { unsafe { Waker::from_raw(noop_raw_waker()) } }

/// Drives a future to completion by busy-polling with a no-op waker.
///
/// This is only valid for futures that make progress on every poll (as ours do), which is the case
/// for the synchronous-completing callbacks used in these tests.
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

// test types

struct Foo([u8; 4]);

bitcoin_consensus_encoding::encoder_newtype! {
    struct FooEncoder<'e>(ArrayEncoder<4>);
}

impl Encode for Foo {
    type Encoder<'e>
        = FooEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        FooEncoder::new(ArrayEncoder::without_length_prefix(self.0))
    }
}

#[derive(Debug, PartialEq)]
struct Bar([u8; 4]);

#[derive(Default)]
struct BarDecoder(ArrayDecoder<4>);

impl Decoder for BarDecoder {
    type Output = Bar;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }
    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Bar) }
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl Decode for Bar {
    type Decoder = BarDecoder;
}

// encode tests

#[test]
fn encode_to_async_writer_collects_all_bytes() {
    let foo = Foo([0xde, 0xad, 0xbe, 0xef]);
    let mut out = Vec::new();
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(encode_to_async_writer(&foo, |_cx, bytes: &[u8]| {
            out.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }));
    result.unwrap();
    assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn encode_to_async_writer_handles_partial_writes() {
    // Callback writes a single byte at a time, exercising the inner chunk loop.
    let foo = Foo([0x01, 0x02, 0x03, 0x04]);
    let mut out = Vec::new();
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(encode_to_async_writer(&foo, |_cx, bytes: &[u8]| {
            out.push(bytes[0]);
            Poll::Ready(Ok(1))
        }));
    result.unwrap();
    assert_eq!(out, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn encode_to_async_writer_pending_then_ready() {
    // First poll on a chunk returns Pending, then makes progress. block_on re-polls.
    let foo = Foo([0xaa, 0xbb, 0xcc, 0xdd]);
    let mut out = Vec::new();
    let mut pend = true;
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(encode_to_async_writer(&foo, |_cx, bytes: &[u8]| {
            if pend {
                pend = false;
                return Poll::Pending;
            }
            pend = true;
            out.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }));
    result.unwrap();
    assert_eq!(out, vec![0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn encode_to_async_writer_propagates_error() {
    let foo = Foo([0; 4]);
    let result: Result<(), AsyncWriteError<&str>> =
        block_on(encode_to_async_writer(&foo, |_cx, _bytes: &[u8]| Poll::Ready(Err("boom"))));
    assert_eq!(result, Err(AsyncWriteError::Write("boom")));
}

#[test]
fn encode_to_async_writer_write_zero_errors() {
    let foo = Foo([0; 4]);
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(encode_to_async_writer(&foo, |_cx, _bytes: &[u8]| Poll::Ready(Ok(0))));
    assert_eq!(result, Err(AsyncWriteError::WriteZero));
}

#[test]
fn encode_to_async_writer_too_many_bytes_errors() {
    let foo = Foo([0; 4]);
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(encode_to_async_writer(&foo, |_cx, bytes: &[u8]| {
            Poll::Ready(Ok(bytes.len() + 1))
        }));
    assert_eq!(result, Err(AsyncWriteError::WroteTooManyBytes));
}

#[test]
fn drain_to_async_writer_works() {
    let foo = Foo([1, 2, 3, 4]);
    let mut encoder = foo.encoder();
    let mut out = Vec::new();
    let result: Result<(), AsyncWriteError<Infallible>> =
        block_on(drain_to_async_writer(&mut encoder, |_cx, bytes: &[u8]| {
            out.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }));
    result.unwrap();
    assert_eq!(out, vec![1, 2, 3, 4]);
}

// decode tests

fn slice_reader(
    data: &[u8],
) -> impl FnMut(&mut Context<'_>, &mut [u8]) -> Poll<Result<usize, Infallible>> + '_ {
    let mut pos = 0;
    move |_cx, dst: &mut [u8]| {
        let n = (data.len() - pos).min(dst.len());
        dst[..n].copy_from_slice(&data[pos..pos + n]);
        pos += n;
        Poll::Ready(Ok(n))
    }
}

#[test]
fn decode_from_async_read_with_buffer_works() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut buffer = [0u8; 64];
    let bar: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(slice_reader(&data), &mut buffer));
    assert_eq!(bar.unwrap(), Bar([0xde, 0xad, 0xbe, 0xef]));
}

#[test]
fn decode_from_async_read_unbuffered_works() {
    let data = [0x01, 0x02, 0x03, 0x04];
    let bar: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_unbuffered(slice_reader(&data)));
    assert_eq!(bar.unwrap(), Bar([0x01, 0x02, 0x03, 0x04]));
}

#[test]
fn decode_from_async_read_small_buffer_streams() {
    // 1-byte buffer forces multiple read+push iterations.
    let data = [0x11, 0x22, 0x33, 0x44];
    let mut buffer = [0u8; 1];
    let bar: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(slice_reader(&data), &mut buffer));
    assert_eq!(bar.unwrap(), Bar([0x11, 0x22, 0x33, 0x44]));
}

#[test]
fn decode_from_async_read_pending_then_ready() {
    let data = [0xaa, 0xbb, 0xcc, 0xdd];
    let mut buffer = [0u8; 64];
    let mut pos = 0;
    let mut pend = true;
    let bar: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(
            |_cx, dst: &mut [u8]| {
                if pend {
                    pend = false;
                    return Poll::Pending;
                }
                pend = true;
                let n = (data.len() - pos).min(dst.len());
                dst[..n].copy_from_slice(&data[pos..pos + n]);
                pos += n;
                Poll::Ready(Ok(n))
            },
            &mut buffer,
        ));
    assert_eq!(bar.unwrap(), Bar([0xaa, 0xbb, 0xcc, 0xdd]));
}

#[test]
fn decode_from_async_read_eof_before_complete_errors() {
    // Only 2 of 4 bytes available, then EOF (Ok(0)).
    let data = [0x01, 0x02];
    let mut buffer = [0u8; 64];
    let result: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(slice_reader(&data), &mut buffer));
    assert!(matches!(result, Err(AsyncReadError::Decode(_))));
}

#[test]
fn decode_from_async_read_empty_buffer_does_not_call_callback() {
    // An empty buffer means no progress is possible, so the callback must never be invoked and the
    // decoder is finalized as EOF (which errors for a non-empty type).
    let mut buffer = [0u8; 0];
    let mut called = false;
    let result: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(
            |_cx, _dst: &mut [u8]| {
                called = true;
                Poll::Ready(Ok(0))
            },
            &mut buffer,
        ));
    assert!(!called, "callback must not be called with an empty buffer");
    assert!(matches!(result, Err(AsyncReadError::Decode(_))));
}

#[test]
fn decode_from_async_read_propagates_read_error() {
    let mut buffer = [0u8; 64];
    let result: Result<Bar, AsyncReadError<UnexpectedEofError, &str>> =
        block_on(decode_from_async_read_with_buffer(
            |_cx, _dst: &mut [u8]| Poll::Ready(Err("io fail")),
            &mut buffer,
        ));
    assert_eq!(result, Err(AsyncReadError::Read("io fail")));
}

#[test]
fn decode_from_async_read_too_many_bytes_errors() {
    let mut buffer = [0u8; 4];
    let result: Result<Bar, AsyncReadError<UnexpectedEofError, Infallible>> =
        block_on(decode_from_async_read_with_buffer(
            |_cx, dst: &mut [u8]| Poll::Ready(Ok(dst.len() + 1)),
            &mut buffer,
        ));
    assert_eq!(result, Err(AsyncReadError::ReadTooManyBytes));
}
