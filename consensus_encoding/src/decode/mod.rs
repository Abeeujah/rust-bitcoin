// SPDX-License-Identifier: CC0-1.0

//! Consensus Decoding Traits

pub mod decoders;

#[cfg(feature = "std")]
use crate::ReadError;
use crate::{AsyncReadError, DecodeError, UnconsumedError};

/// A Bitcoin object which can be consensus-decoded using a push decoder.
///
/// To decode something, create a [`Self::Decoder`] and push byte slices into it with
/// [`Decoder::push_bytes`], then call [`Decoder::end`] to get the result.
///
/// # Examples
///
/// ```
/// use bitcoin_consensus_encoding::{decode_from_slice, Decode, Decoder, DecoderStatus, ArrayDecoder, UnexpectedEofError};
///
/// struct Foo([u8; 4]);
///
/// #[derive(Default)]
/// struct FooDecoder(ArrayDecoder<4>);
///
/// impl Decoder for FooDecoder {
///     type Output = Foo;
///     type Error = UnexpectedEofError;
///
///     fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
///         self.0.push_bytes(bytes)
///     }
///     fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Foo) }
///     fn read_limit(&self) -> usize { self.0.read_limit() }
/// }
///
/// impl Decode for Foo {
///     type Decoder = FooDecoder;
/// }
///
/// let foo: Foo = decode_from_slice(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
/// assert_eq!(foo.0, [0xde, 0xad, 0xbe, 0xef]);
/// ```
pub trait Decode {
    /// Associated decoder for the type.
    type Decoder: Decoder<Output = Self> + Default;

    /// Constructs a "default decoder" for the type.
    fn decoder() -> Self::Decoder { Self::Decoder::default() }
}

/// A push decoder for a consensus-decodable object.
pub trait Decoder: Sized {
    /// The type that this decoder produces when decoding is complete.
    type Output;
    /// The error type that this decoder can produce.
    type Error;

    /// Pushes bytes into the decoder, consuming as much as possible.
    ///
    /// The slice reference will be advanced to point to the unconsumed portion. Returns
    /// `Ok(DecoderStatus::NeedsMore)` if more bytes are needed to complete decoding,
    /// `Ok(DecoderStatus::Ready)` if the decoder is ready to finalize with [`Self::end`], or
    /// `Err(error)` if parsing failed.
    ///
    /// Once the decoder returns `Ok(DecoderStatus::Ready)`, subsequent calls to this method will
    /// continue to return `Ok(DecoderStatus::Ready)` without consuming additional bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according to the decoder's
    /// validation rules. Insufficient data (needing more bytes) is *not* an error for this method,
    /// the decoder will simply consume what it can and return `DecoderStatus::NeedsMore` to
    /// indicate more data is needed.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    #[track_caller]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error>;

    /// Completes the decoding process and returns the final result.
    ///
    /// This consumes the decoder and should be called when no more input data is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the decoder has not received sufficient data to complete decoding, or if
    /// the accumulated data is invalid when considered as a complete object.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    #[track_caller]
    fn end(self) -> Result<Self::Output, Self::Error>;

    /// Returns the maximum number of bytes this decoder can consume without over-reading.
    ///
    /// Returns 0 if the decoder is complete and ready to finalize with [`Self::end`]. This is used
    /// by [`decode_from_read_unbuffered`] to optimize read sizes, avoiding both inefficient
    /// under-reads and unnecessary over-reads.
    fn read_limit(&self) -> usize;
}

/// Indicates whether a decoder needs more data or is ready to finalize.
///
/// This is returned from the [`Decoder::push_bytes`] method to indicate whether the decoder
/// should continue accumulating data or is ready to produce the decoded value with [`Decoder::end`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DecoderStatus {
    /// The decoder needs more data to complete decoding.
    ///
    /// Continue pushing byte slices with [`Decoder::push_bytes`] until this status changes to
    /// [`Ready`](DecoderStatus::Ready).
    NeedsMore,

    /// The decoder has accumulated sufficient data and is ready to finalize.
    ///
    /// Call [`Decoder::end`] to complete the decoding process and obtain the final result.
    Ready,
}

impl DecoderStatus {
    /// Returns `true` if the decoder needs more data to continue.
    pub fn needs_more(&self) -> bool { matches!(self, Self::NeedsMore) }

    /// Returns `true` if ready to produce decoded value with [`Decoder::end`].
    pub fn is_ready(&self) -> bool { matches!(self, Self::Ready) }
}

/// Decodes an object from a byte slice.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data. This function also errors if the provided slice is not completely consumed
/// during decode.
pub fn decode_from_slice<T: Decode>(
    bytes: &[u8],
) -> Result<T, DecodeError<<T::Decoder as Decoder>::Error>> {
    let mut remaining = bytes;
    let data = decode_from_slice_unbounded::<T>(&mut remaining).map_err(DecodeError::Parse)?;

    if remaining.is_empty() {
        Ok(data)
    } else {
        Err(DecodeError::Unconsumed(UnconsumedError()))
    }
}

/// Decodes an object from an unbounded byte slice.
///
/// Unlike [`decode_from_slice`], this function will not error if the slice contains additional
/// bytes that are not required to decode. Furthermore, the byte slice reference provided to this
/// function will be updated based on the consumed data, returning the unconsumed bytes.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data.
pub fn decode_from_slice_unbounded<T>(
    bytes: &mut &[u8],
) -> Result<T, <T::Decoder as Decoder>::Error>
where
    T: Decode,
{
    let mut decoder = T::decoder();

    while !bytes.is_empty() {
        if decoder.push_bytes(bytes)?.is_ready() {
            break;
        }
    }

    decoder.end()
}

/// Decodes an object from a buffered reader.
///
/// # Performance
///
/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
/// your reader with [`std::io::BufReader`] in order to use this function. This avoids frequent
/// small reads, which can significantly impact performance.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read<T, R>(mut reader: R) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::BufRead,
{
    let mut decoder = T::decoder();

    loop {
        let mut buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            // Auto retry read for non-fatal error.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadError::Io(error)),
        };

        if buffer.is_empty() {
            // EOF, but still try to finalize the decoder.
            return decoder.end().map_err(ReadError::Decode);
        }

        let original_len = buffer.len();
        let status = decoder.push_bytes(&mut buffer).map_err(ReadError::Decode)?;
        let consumed = original_len - buffer.len();
        reader.consume(consumed);

        if status.is_ready() {
            return decoder.end().map_err(ReadError::Decode);
        }
    }
}

/// Decodes an object from an unbuffered reader using a fixed-size buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`]. This function is
/// only needed when you have an unbuffered reader which you cannot wrap. It will probably have
/// worse performance.
///
/// # Buffer
///
/// Uses a fixed 4KB (4096 bytes) stack-allocated buffer that is reused across read operations. This
/// size is a good balance between memory usage and system call efficiency for most use cases.
///
/// For different buffer sizes, use [`decode_from_read_unbuffered_with`].
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read_unbuffered<T, R>(
    reader: R,
) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::Read,
{
    decode_from_read_unbuffered_with::<T, R, 4096>(reader)
}

/// Decodes an object from an unbuffered reader using a custom-sized buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`]. This function is
/// only needed when you have an unbuffered reader which you cannot wrap. It will probably have
/// worse performance.
///
/// # Buffer
///
/// The `BUFFER_SIZE` parameter controls the intermediate buffer size used for reading. The buffer
/// is allocated on the stack (not heap) and reused across read operations. Larger buffers reduce
/// the number of system calls, but use more memory.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read_unbuffered_with<T, R, const BUFFER_SIZE: usize>(
    mut reader: R,
) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::Read,
{
    let mut decoder = T::decoder();
    let mut buffer = [0u8; BUFFER_SIZE];

    while decoder.read_limit() > 0 {
        // Only read what we need, up to buffer size.
        let clamped_buffer = &mut buffer[..decoder.read_limit().min(BUFFER_SIZE)];
        match reader.read(clamped_buffer) {
            Ok(0) => {
                // EOF, but still try to finalize the decoder.
                return decoder.end().map_err(ReadError::Decode);
            }
            Ok(bytes_read) => {
                if decoder
                    .push_bytes(&mut &clamped_buffer[..bytes_read])
                    .map_err(ReadError::Decode)?
                    .is_ready()
                {
                    return decoder.end().map_err(ReadError::Decode);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Auto retry read for non-fatal error.
            }
            Err(e) => return Err(ReadError::Io(e)),
        }
    }

    decoder.end().map_err(ReadError::Decode)
}

/// Decodes an object using an async poll-read callback and a caller-provided buffer.
///
/// This is the runtime-neutral, `no_std`-compatible async equivalent of
/// [`decode_from_read_unbuffered`], the caller supplies a callback with
/// [`poll_read`]-like semantics, which can adapt any async runtime (tokio, smol, embassy, ...).
///
/// The `buffer` is reused across reads. Because, unlike the `unbuffered` variants, the buffer is
/// owned by the caller, it does not become part of the returned future. This makes it the preferred
/// choice for `no_std`/embedded callers who want to control the buffer's size and location.
///
/// The callback is called with the current [`Context`] and a mutable buffer slice. It must
/// eventually return:
///
/// * `Poll::Ready(Ok(n))` with `n <= buffer.len()` indicating `n` bytes were read (`n == 0`
///   signals EOF), or
/// * `Poll::Ready(Err(e))` if reading failed, or
/// * `Poll::Pending` after arranging for the current task to be woken.
///
/// [`poll_read`]: https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html#tymethod.poll_read
///
/// # Errors
///
/// Returns [`AsyncReadError::Read`] if the callback errors, [`AsyncReadError::Decode`] if the
/// decoder errors, or [`AsyncReadError::ReadTooManyBytes`] if the callback reports reading more
/// bytes than the provided buffer length.
///
/// Returning [`Poll::Pending`] from the callback has normal [`poll_read`] semantics: no bytes are
/// considered read for that call and the task must be arranged to wake when progress is possible.
/// The callback is only invoked with a non-empty destination slice; an empty `buffer` is treated as
/// EOF and the decoder is finalized without calling the callback.
///
/// # Cancellation
///
/// This future is not restartably cancellation-safe. If it is dropped before completion, bytes may
/// already have been read from the underlying reader and incorporated into the (now dropped) decoder
/// state. Restarting a decode on the same reader would therefore lose those bytes.
///
/// [`Poll::Pending`]: core::task::Poll::Pending
///
/// # Examples
///
/// ```
/// # use core::task::{Context, Poll};
/// # use bitcoin_consensus_encoding::{decode_from_async_read_with_buffer, AsyncReadError, Decode, Decoder, DecoderStatus, ArrayDecoder, UnexpectedEofError};
/// # #[derive(Debug, PartialEq)] struct Foo([u8; 4]);
/// # #[derive(Default)] struct FooDecoder(ArrayDecoder<4>);
/// # impl Decoder for FooDecoder {
/// #     type Output = Foo;
/// #     type Error = UnexpectedEofError;
/// #     fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> { self.0.push_bytes(bytes) }
/// #     fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Foo) }
/// #     fn read_limit(&self) -> usize { self.0.read_limit() }
/// # }
/// # impl Decode for Foo { type Decoder = FooDecoder; }
/// # async fn run() -> Result<(), AsyncReadError<UnexpectedEofError, core::convert::Infallible>> {
/// let data = [0xde, 0xad, 0xbe, 0xef];
/// let mut pos = 0;
/// let mut buffer = [0u8; 64];
/// // A trivial synchronous-completing callback that reads from an in-memory slice.
/// let foo: Foo = decode_from_async_read_with_buffer(|_cx: &mut Context<'_>, dst: &mut [u8]| {
///     let n = (data.len() - pos).min(dst.len());
///     dst[..n].copy_from_slice(&data[pos..pos + n]);
///     pos += n;
///     Poll::Ready(Ok(n))
/// }, &mut buffer).await?;
/// assert_eq!(foo, Foo([0xde, 0xad, 0xbe, 0xef]));
/// # Ok(())
/// # }
/// ```
///
/// Adapting a real async reader is a matter of forwarding to its `poll_read`. For a
/// [`futures::io::AsyncRead`] (whose `poll_read` maps 1:1 to the callback) it looks like this:
///
/// ```ignore
/// use core::pin::Pin;
/// use futures::io::AsyncRead;
/// use bitcoin_consensus_encoding::{decode_from_async_read_with_buffer, AsyncReadError, Decode, Decoder};
///
/// async fn read_it<T: Decode, R: AsyncRead + Unpin>(
///     mut reader: R,
///     buffer: &mut [u8],
/// ) -> Result<T, AsyncReadError<<T::Decoder as Decoder>::Error, std::io::Error>> {
///     decode_from_async_read_with_buffer(|cx, dst| Pin::new(&mut reader).poll_read(cx, dst), buffer).await
/// }
/// ```
///
/// [`futures::io::AsyncRead`]: https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html
pub async fn decode_from_async_read_with_buffer<T, R, E>(
    mut poll_read: R,
    buffer: &mut [u8],
) -> Result<T, AsyncReadError<<T::Decoder as Decoder>::Error, E>>
where
    T: Decode,
    R: FnMut(&mut core::task::Context<'_>, &mut [u8]) -> core::task::Poll<Result<usize, E>>,
{
    let mut decoder = T::decoder();

    while decoder.read_limit() > 0 {
        let limit = decoder.read_limit().min(buffer.len());
        if limit == 0 {
            // Reachable when `buffer` is empty but the decoder still needs input. No progress is
            // possible, so treat it like EOF and let the decoder finalize (or error).
            return decoder.end().map_err(AsyncReadError::Decode);
        }

        let dst = &mut buffer[..limit];
        let bytes_read =
            core::future::poll_fn(|cx| poll_read(cx, dst)).await.map_err(AsyncReadError::Read)?;

        if bytes_read > limit {
            return Err(AsyncReadError::ReadTooManyBytes);
        }
        if bytes_read == 0 {
            // EOF, but still try to finalize the decoder.
            return decoder.end().map_err(AsyncReadError::Decode);
        }

        let mut input = &buffer[..bytes_read];
        let status = decoder.push_bytes(&mut input).map_err(AsyncReadError::Decode)?;
        debug_assert!(
            input.is_empty(),
            "decoder.read_limit() allowed bytes that push_bytes did not consume"
        );
        if status.is_ready() {
            return decoder.end().map_err(AsyncReadError::Decode);
        }
    }

    decoder.end().map_err(AsyncReadError::Decode)
}

/// Decodes an object using an async poll-read callback and a 4096 byte internal buffer.
///
/// This is the async equivalent of [`decode_from_read_unbuffered`]. The internal buffer becomes
/// part of the returned future; `no_std`/embedded callers may prefer
/// [`decode_from_async_read_with_buffer`] or [`decode_from_async_read_unbuffered_with`] with a
/// smaller buffer.
///
/// See [`decode_from_async_read_with_buffer`] for the callback contract.
///
/// # Errors
///
/// See [`decode_from_async_read_with_buffer`].
pub async fn decode_from_async_read_unbuffered<T, R, E>(
    poll_read: R,
) -> Result<T, AsyncReadError<<T::Decoder as Decoder>::Error, E>>
where
    T: Decode,
    R: FnMut(&mut core::task::Context<'_>, &mut [u8]) -> core::task::Poll<Result<usize, E>>,
{
    decode_from_async_read_unbuffered_with::<T, R, E, 4096>(poll_read).await
}

/// Decodes an object using an async poll-read callback and a custom-sized internal buffer.
///
/// This is the async equivalent of [`decode_from_read_unbuffered_with`]. The internal
/// `BUFFER_SIZE`-byte buffer becomes part of the returned future.
///
/// See [`decode_from_async_read_with_buffer`] for the callback contract.
///
/// # Errors
///
/// See [`decode_from_async_read_with_buffer`].
pub async fn decode_from_async_read_unbuffered_with<T, R, E, const BUFFER_SIZE: usize>(
    poll_read: R,
) -> Result<T, AsyncReadError<<T::Decoder as Decoder>::Error, E>>
where
    T: Decode,
    R: FnMut(&mut core::task::Context<'_>, &mut [u8]) -> core::task::Poll<Result<usize, E>>,
{
    let mut buffer = [0u8; BUFFER_SIZE];
    decode_from_async_read_with_buffer::<T, R, E>(poll_read, &mut buffer).await
}

/// Checks that the given bytes decode to the expected value, panicking if they don't.
///
/// This is intended for tests only.
///
/// # Panics
///
/// If the decoded value doesn't match the expected value, or if decoding fails.
#[track_caller]
pub fn check_decode<T: Decode + Eq + core::fmt::Debug>(bytes: &[u8], expected: &T)
where
    <T::Decoder as Decoder>::Error: core::fmt::Debug,
{
    let decoder = T::decoder();
    check_decoder(decoder, bytes, expected);
}

/// Checks that the given `decoder` produces the expected value, panicking if it doesn't.
///
/// This is intended for tests only.
///
/// # Panics
///
/// If the decoder doesn't produce the expected value or if decoding fails.
#[track_caller]
pub fn check_decoder<D: Decoder>(mut decoder: D, mut bytes: &[u8], expected: &D::Output)
where
    D::Output: Eq + core::fmt::Debug,
    D::Error: core::fmt::Debug,
{
    loop {
        match decoder.push_bytes(&mut bytes) {
            Ok(status) => {
                if status.is_ready() {
                    break;
                }
                assert!(!bytes.is_empty(), "decoder needs more data but no bytes remaining");
            }
            Err(e) => panic!("decoder failed with error: {e:?}"),
        }
    }

    match decoder.end() {
        Ok(result) => {
            assert_eq!(&result, expected, "decoded value doesn't match expected value");
        }
        Err(e) => panic!("decoder finalization failed with error: {e:?}"),
    }
}
