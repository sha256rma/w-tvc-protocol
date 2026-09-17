//! Weight loading, quantisation, and the weight commitment `C`.
//!
//! # Two layers, deliberately separated
//!
//! This module is split into a *scheme* layer and a *protocol* layer, because
//! conflating them is what makes a commitment interface impossible to change
//! later.
//!
//! - **Scheme layer.** [`VectorCommitment`] commits to a bare `&[FieldElement]`.
//!   It knows nothing about tensors, dtypes or quantisation scales.
//!   [`MerkleVectorCommitment`] is the implementation for this phase; its
//!   commitment is a 32-byte root plus a length. A KZG or Pedersen scheme would
//!   have a group element instead, which is why `Commitment`, `Proof`,
//!   `PublicParams` and `Error` are all associated types.
//! - **Protocol layer.** [`WeightCommitment`] is what gets published and signed.
//!   It binds the scheme's commitment together with the element count, the
//!   fixed-point scale, and a digest of the tensor manifest:
//!
//!   ```text
//!   C = tagged_hash(WEIGHT_ROOT, [scheme, scheme_commitment,
//!                                 length, fractional_bits, manifest_digest])
//!   ```
//!
//! The payoff is that **`C` is always 32 bytes, whatever the underlying scheme**,
//! because it is always a tagged hash. [`crate::signer`] and [`crate::registry`]
//! only ever see `C`, so swapping the scheme never touches them. The tensor
//! manifest also belongs here rather than in the trait — a polynomial commitment
//! has no notion of a tensor.
//!
//! # What is being committed, and why that shape
//!
//! A registry entry has to pin down *the weights*, not a file. Two publishers can
//! ship byte-identical tensors in files that differ in padding, key order, or
//! metadata, and one publisher can reshape a tensor without changing a single
//! float. So the pipeline throws away what must not matter and keeps what must:
//!
//! ```text
//!   tensors ──quantise──> field vector ──commit──> scheme commitment ──bind──> C
//! ```
//!
//! **Quantise.** Every element becomes a fixed-point integer at a declared number
//! of fractional bits, then a canonical residue in the BN254 scalar field (see
//! [`FieldElement`]). Committing to floats directly would make the commitment
//! hostage to `f32` bit patterns — `-0.0` and `0.0`, or two NaN payloads, are the
//! same weight but different bytes.
//!
//! **Commit.** A SHA-256 Merkle tree over the field vector. This is what makes the
//! commitment *openable*: a publisher can prove `W[i] = v` against a registered
//! `C` without shipping the whole model.
//!
//! **Bind.** Without the manifest, a `[2, 3]` tensor and a `[3, 2]` tensor holding
//! the same numbers would commit identically; without the count, the tree's shape
//! would be ambiguous.
//!
//! # An honest note on the field
//!
//! The vector is *encoded* into BN254's scalar field, but no modular arithmetic is
//! performed and the tree hash is SHA-256, which is bitwise and expensive to
//! verify inside an arithmetic circuit (tens of thousands of constraints per
//! compression). Calling this a "field vector commitment" would overclaim: it is a
//! **tagged SHA-256 Merkle commitment over BN254 field-encoded weights**. The
//! encoding means the vector needs no re-encoding when a circuit arrives; it does
//! not by itself make anything circuit-efficient. A field-native hash (Poseidon)
//! is the change that would, and it is deferred until the proving system is chosen.

use std::collections::BTreeMap;
use std::path::Path;

use crate::digest::{
    tagged_hash, DOMAIN_TENSOR_MANIFEST, DOMAIN_WEIGHT_LEAF, DOMAIN_WEIGHT_NODE, DOMAIN_WEIGHT_ROOT,
};
use crate::error::{Result, TvcError};
use crate::hex;

/// Identifier for the commitment scheme implemented by [`MerkleVectorCommitment`].
///
/// Absorbed into [`WeightCommitment::root`], so a root produced by a future KZG
/// scheme can never be mistaken for a Merkle root even if the 32 bytes collided.
pub const MERKLE_SCHEME_TAG: &str = "merkle-sha256/v1";

/// Modulus of the BN254 scalar field, big-endian.
///
/// The field is BN254's scalar field rather than an arbitrary prime because that
/// is the field a circuit over this weight vector would operate in. The
/// commitment therefore does not need re-encoding when the circuit layer lands.
pub const FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// A canonical residue in the BN254 scalar field, big-endian.
///
/// Signed fixed-point values map into the field the standard way: a negative `v`
/// becomes `p - |v|`. Because `|v| < 2^127` and `p ≈ 2^254`, every value this
/// crate produces is canonical by construction, and the two halves of the field
/// never overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldElement([u8; 32]);

impl FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Maps a signed fixed-point integer into the field.
    pub fn from_i128(value: i128) -> Self {
        let mut magnitude = [0u8; 32];
        magnitude[16..].copy_from_slice(&value.unsigned_abs().to_be_bytes());
        if value < 0 {
            Self(sub_be(&FIELD_MODULUS, &magnitude))
        } else {
            Self(magnitude)
        }
    }

    /// Big-endian canonical encoding.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Builds an element from big-endian bytes, rejecting non-canonical input.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedHex`] if `bytes` is not strictly less than
    /// [`FIELD_MODULUS`]; two encodings of one residue would break the injectivity
    /// the Merkle leaves rely on.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes >= FIELD_MODULUS {
            return Err(TvcError::MalformedHex(format!(
                "field element {} is not a canonical residue",
                hex::encode(&bytes)
            )));
        }
        Ok(Self(bytes))
    }

    /// Lowercase hex rendering.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Big-endian 256-bit subtraction, used only for the negative-value mapping.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let diff = i16::from(a[index]) - i16::from(b[index]) - borrow;
        if diff < 0 {
            out[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[index] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// Element types this crate knows how to quantise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dtype {
    /// IEEE 754 double precision.
    F64,
    /// IEEE 754 single precision.
    F32,
    /// IEEE 754 half precision.
    F16,
    /// Brain floating point, the truncated top half of an `f32`.
    BF16,
    /// Signed 64-bit integer.
    I64,
    /// Signed 32-bit integer.
    I32,
    /// Signed 16-bit integer.
    I16,
    /// Signed 8-bit integer.
    I8,
    /// Unsigned 8-bit integer.
    U8,
}

impl Dtype {
    /// Width of one element in bytes.
    pub fn width(self) -> usize {
        match self {
            Self::F64 | Self::I64 => 8,
            Self::F32 | Self::I32 => 4,
            Self::F16 | Self::BF16 | Self::I16 => 2,
            Self::I8 | Self::U8 => 1,
        }
    }

    /// The safetensors spelling of this dtype.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::F64 => "F64",
            Self::F32 => "F32",
            Self::F16 => "F16",
            Self::BF16 => "BF16",
            Self::I64 => "I64",
            Self::I32 => "I32",
            Self::I16 => "I16",
            Self::I8 => "I8",
            Self::U8 => "U8",
        }
    }

    /// Parses a safetensors dtype string.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnsupportedDtype`] for types this crate does not
    /// quantise, including `BOOL` and the FP8 variants.
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "F64" => Ok(Self::F64),
            "F32" => Ok(Self::F32),
            "F16" => Ok(Self::F16),
            "BF16" => Ok(Self::BF16),
            "I64" => Ok(Self::I64),
            "I32" => Ok(Self::I32),
            "I16" => Ok(Self::I16),
            "I8" => Ok(Self::I8),
            "U8" => Ok(Self::U8),
            other => Err(TvcError::UnsupportedDtype(other.to_owned())),
        }
    }

    /// Decodes one little-endian element to `f64`.
    ///
    /// safetensors stores every dtype little-endian, so the decode is fixed.
    fn decode(self, raw: &[u8]) -> f64 {
        match self {
            Self::F64 => f64::from_le_bytes(raw.try_into().expect("width checked")),
            Self::F32 => f64::from(f32::from_le_bytes(raw.try_into().expect("width checked"))),
            Self::F16 => f64::from(f16_to_f32(u16::from_le_bytes(
                raw.try_into().expect("width checked"),
            ))),
            Self::BF16 => f64::from(bf16_to_f32(u16::from_le_bytes(
                raw.try_into().expect("width checked"),
            ))),
            Self::I64 => i64::from_le_bytes(raw.try_into().expect("width checked")) as f64,
            Self::I32 => f64::from(i32::from_le_bytes(raw.try_into().expect("width checked"))),
            Self::I16 => f64::from(i16::from_le_bytes(raw.try_into().expect("width checked"))),
            Self::I8 => f64::from(raw[0] as i8),
            Self::U8 => f64::from(raw[0]),
        }
    }
}

/// Widens an IEEE half-precision value.
///
/// The subnormal branch is computed in arithmetic rather than by renormalising
/// bits: a half subnormal is `frac * 2^-24` with `frac < 1024`, and both factors
/// are exactly representable in `f32`, so the multiplication is exact.
fn f16_to_f32(bits: u16) -> f32 {
    let sign = if bits >> 15 == 1 { -1.0f32 } else { 1.0f32 };
    let exponent = (bits >> 10) & 0x1f;
    let fraction = u32::from(bits & 0x03ff);

    match exponent {
        0 => sign * (fraction as f32) / 16_777_216.0,
        0x1f => {
            let raw = (u32::from(bits >> 15) << 31) | (0xff << 23) | (fraction << 13);
            f32::from_bits(raw)
        }
        _ => {
            let raw = (u32::from(bits >> 15) << 31)
                | ((u32::from(exponent) + 127 - 15) << 23)
                | (fraction << 13);
            f32::from_bits(raw)
        }
    }
}

/// Widens a bfloat16 value.
///
/// bf16 is bit-for-bit the high half of an `f32` — same 8-bit exponent, same bias
/// of 127 — so the shift is exact for every input, including subnormals,
/// infinities and NaNs. No special cases are needed or correct here.
fn bf16_to_f32(bits: u16) -> f32 {
    f32::from_bits(u32::from(bits) << 16)
}

/// One named tensor's raw bytes, as read from a model file or synthesised.
#[derive(Clone, Debug, PartialEq)]
pub struct Tensor {
    /// Tensor name, for example `model.layers.0.self_attn.q_proj.weight`.
    pub name: String,
    /// Element type.
    pub dtype: Dtype,
    /// Dimensions, outermost first.
    pub shape: Vec<u64>,
    /// Little-endian element data, `shape.product() * dtype.width()` bytes.
    pub data: Vec<u8>,
}

impl Tensor {
    /// Builds a tensor from `f32` values, checking the shape against the data.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedTensorFile`] if `shape` does not describe
    /// exactly `values.len()` elements.
    pub fn from_f32(name: impl Into<String>, shape: Vec<u64>, values: &[f32]) -> Result<Self> {
        let name = name.into();
        let expected = element_count(&shape);
        if expected != values.len() as u128 {
            return Err(TvcError::MalformedTensorFile(format!(
                "tensor {name}: shape describes {expected} elements, got {}",
                values.len()
            )));
        }
        let mut data = Vec::with_capacity(values.len() * 4);
        for value in values {
            data.extend_from_slice(&value.to_le_bytes());
        }
        Ok(Self {
            name,
            dtype: Dtype::F32,
            shape,
            data,
        })
    }

    /// Number of elements described by [`Self::shape`].
    pub fn element_count(&self) -> u128 {
        element_count(&self.shape)
    }
}

fn element_count(shape: &[u64]) -> u128 {
    shape.iter().map(|d| u128::from(*d)).product::<u128>()
}

/// Structural description of one tensor, without its data.
///
/// This is what [`WeightVector::manifest_digest`] commits to, so that reshaping a
/// tensor or renaming a layer changes the commitment even when every number is
/// unchanged. Because the manifest is folded in commitment order and each entry
/// carries its element count, the committed sequence also fixes every tensor's
/// offset within the flattened vector — there is no separate offset to bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorSpec {
    /// Tensor name.
    pub name: String,
    /// Element type.
    pub dtype: Dtype,
    /// Dimensions, outermost first.
    pub shape: Vec<u64>,
    /// Number of elements this tensor contributes to the weight vector.
    pub length: u64,
}

/// Fixed-point quantiser mapping real-valued weights to field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quantizer {
    fractional_bits: u32,
}

impl Quantizer {
    /// Fractional bits used when a publisher expresses no preference.
    ///
    /// Sixteen bits give a step of `2^-16 ≈ 1.5e-5`. Perturbations below half a
    /// step are absorbed; everything larger separates.
    ///
    /// Note what this does *not* buy. The step is far **finer** than the
    /// precision of `bf16` (ULP ≈ `7.8e-3` near 1.0) or of int8, so a checkpoint
    /// re-encoded through a narrower dtype moves by hundreds of steps and commits
    /// to a different `C`. That is the correct behaviour for a scheme that
    /// commits to the weights as stored — a `bf16` copy is not the `f32`
    /// original — but it means the scale is a policy choice rather than a free
    /// parameter: coarsening it buys tolerance to re-encoding and pays for it by
    /// failing to separate models that genuinely differ by less than one step.
    pub const DEFAULT_FRACTIONAL_BITS: u32 = 16;

    /// Hard ceiling on fractional bits.
    ///
    /// This is only the ceiling on the *parameter*. The binding constraint is
    /// [`Self::PRECISION_BOUND`], which applies per value: a scale is usable only
    /// where `|v · 2^B| < 2^53`. The two interact, and at the ceiling the
    /// interaction is severe — `B = 48` admits only `|v| < 32`. Use
    /// [`Self::max_safe_fractional_bits`] to pick a scale that fits real tensors
    /// rather than assuming the ceiling is reachable.
    pub const MAX_FRACTIONAL_BITS: u32 = 48;

    /// Largest magnitude for which `f64` represents every integer exactly, `2^53`.
    ///
    /// Above this the representable grid is coarser than one unit, so a quantised
    /// value no longer carries the "within half a step of `2^-B`" meaning the
    /// scale advertises. The multiplication itself stays exact — scaling by a
    /// power of two only shifts the exponent — so this bound is about *fidelity*,
    /// not about determinism. Rejecting is better than silently returning an
    /// integer that means something coarser than the scale claims.
    pub const PRECISION_BOUND: f64 = 9_007_199_254_740_992.0;

    /// Builds a quantiser at the given number of fractional bits.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] if `fractional_bits` exceeds
    /// [`Self::MAX_FRACTIONAL_BITS`].
    pub fn new(fractional_bits: u32) -> Result<Self> {
        if fractional_bits > Self::MAX_FRACTIONAL_BITS {
            return Err(TvcError::InvalidIdentifier {
                field: "fractional_bits",
                reason: format!(
                    "must be at most {}, got {fractional_bits}",
                    Self::MAX_FRACTIONAL_BITS
                ),
            });
        }
        Ok(Self { fractional_bits })
    }

    /// The largest scale at which every value up to `max_abs` stays exact.
    ///
    /// A publisher who has scanned their tensors for the largest magnitude can
    /// use this to choose a scale that will not trip [`Self::PRECISION_BOUND`].
    /// Returns `0` when no scale works, which means `max_abs` is already past the
    /// bound and [`Self::quantize`] will reject it whatever the scale.
    ///
    /// Computed by testing the bound rather than from `53 - ⌈log2(max_abs)⌉`,
    /// which is off by one at every exact power of two: at `max_abs = 1024` that
    /// formula yields 43, and `1024 · 2^43` is exactly `2^53` — the first value
    /// the bound excludes. Deriving the answer from the same comparison
    /// `quantize` performs makes the two impossible to disagree.
    pub fn max_safe_fractional_bits(max_abs: f64) -> u32 {
        if !max_abs.is_finite() || max_abs <= 0.0 {
            return Self::MAX_FRACTIONAL_BITS;
        }
        let mut bits = Self::MAX_FRACTIONAL_BITS;
        while bits > 0 && max_abs * (1u64 << bits) as f64 >= Self::PRECISION_BOUND {
            bits -= 1;
        }
        bits
    }

    /// The declared scale, in fractional bits.
    pub fn fractional_bits(self) -> u32 {
        self.fractional_bits
    }

    /// Quantises one value to a fixed-point integer.
    ///
    /// Scaling is by an exact power of two, which in IEEE 754 only shifts the
    /// exponent and so is lossless; `f64::round` then rounds half away from zero.
    /// The result is therefore fully determined by IEEE 754. Note that this is a
    /// single multiply with no addend, so there is no multiply-add for a compiler
    /// to contract into an FMA, and Rust does not enable float contraction
    /// regardless.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::QuantizationOverflow`] for NaN, infinities, and values
    /// whose scaled magnitude reaches [`Self::PRECISION_BOUND`].
    pub fn quantize(self, tensor: &str, value: f64) -> Result<i128> {
        if !value.is_finite() {
            return Err(TvcError::QuantizationOverflow {
                tensor: tensor.to_owned(),
                value: value.to_string(),
            });
        }
        let scaled = (value * (1u64 << self.fractional_bits) as f64).round();
        if scaled.abs() >= Self::PRECISION_BOUND {
            return Err(TvcError::QuantizationOverflow {
                tensor: tensor.to_owned(),
                value: value.to_string(),
            });
        }
        Ok(scaled as i128)
    }
}

impl Default for Quantizer {
    fn default() -> Self {
        Self {
            fractional_bits: Self::DEFAULT_FRACTIONAL_BITS,
        }
    }
}

/// A model's weights as a flat, ordered vector of field elements.
///
/// Tensors are concatenated in lexicographic name order, not file order. File
/// order is an artefact of whatever wrote the checkpoint and is not stable across
/// serialisers; sorting makes the vector a pure function of the tensors
/// themselves, so two honest publishers of the same model reach the same `C`.
#[derive(Clone, Debug, PartialEq)]
pub struct WeightVector {
    elements: Vec<FieldElement>,
    manifest: Vec<TensorSpec>,
    fractional_bits: u32,
}

impl WeightVector {
    /// Quantises a set of tensors into a weight vector.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedTensorFile`] for a tensor whose data length
    /// disagrees with its shape or whose name is duplicated, and
    /// [`TvcError::QuantizationOverflow`] for a value the scale cannot represent.
    pub fn from_tensors(tensors: Vec<Tensor>, quantizer: Quantizer) -> Result<Self> {
        let mut ordered: BTreeMap<String, Tensor> = BTreeMap::new();
        for tensor in tensors {
            if let Some(previous) = ordered.insert(tensor.name.clone(), tensor) {
                return Err(TvcError::MalformedTensorFile(format!(
                    "duplicate tensor name {}",
                    previous.name
                )));
            }
        }

        let mut elements = Vec::new();
        let mut manifest = Vec::new();

        for (name, tensor) in ordered {
            let count = tensor.element_count();
            let width = tensor.dtype.width();
            let expected_bytes = count
                .checked_mul(width as u128)
                .ok_or_else(|| TvcError::MalformedTensorFile(format!("tensor {name}: shape overflows")))?;
            if expected_bytes != tensor.data.len() as u128 {
                return Err(TvcError::MalformedTensorFile(format!(
                    "tensor {name}: shape describes {expected_bytes} bytes, data holds {}",
                    tensor.data.len()
                )));
            }

            for raw in tensor.data.chunks_exact(width) {
                let value = tensor.dtype.decode(raw);
                elements.push(FieldElement::from_i128(quantizer.quantize(&name, value)?));
            }

            manifest.push(TensorSpec {
                name,
                dtype: tensor.dtype,
                shape: tensor.shape,
                length: count as u64,
            });
        }

        Ok(Self {
            elements,
            manifest,
            fractional_bits: quantizer.fractional_bits(),
        })
    }

    /// Loads and quantises a `.safetensors` file from disk.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Io`] if the file cannot be read, and any error from
    /// [`Self::from_safetensors_bytes`].
    pub fn from_safetensors_file(path: impl AsRef<Path>, quantizer: Quantizer) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_safetensors_bytes(&bytes, quantizer)
    }

    /// Parses and quantises a safetensors buffer.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedTensorFile`] if the header is not well formed
    /// or a tensor's declared byte range falls outside the data segment, and
    /// [`TvcError::UnsupportedDtype`] for an element type this crate cannot
    /// quantise.
    pub fn from_safetensors_bytes(bytes: &[u8], quantizer: Quantizer) -> Result<Self> {
        Self::from_tensors(parse_safetensors(bytes)?, quantizer)
    }

    /// The quantised weights, in commitment order.
    pub fn elements(&self) -> &[FieldElement] {
        &self.elements
    }

    /// Structural description of the tensors behind the vector.
    pub fn manifest(&self) -> &[TensorSpec] {
        &self.manifest
    }

    /// Number of committed elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Whether the vector holds no elements.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// The fixed-point scale this vector was quantised at.
    pub fn fractional_bits(&self) -> u32 {
        self.fractional_bits
    }

    /// Digest over tensor names, dtypes and shapes, in commitment order.
    ///
    /// Folded as a chain so the digest depends on tensor order as well as
    /// content, and absorbed into [`WeightCommitment::root`].
    pub fn manifest_digest(&self) -> [u8; 32] {
        let mut accumulator = [0u8; 32];
        for spec in &self.manifest {
            let mut shape_bytes = Vec::with_capacity(spec.shape.len() * 8);
            for dimension in &spec.shape {
                shape_bytes.extend_from_slice(&dimension.to_be_bytes());
            }
            accumulator = tagged_hash(
                DOMAIN_TENSOR_MANIFEST,
                &[
                    &accumulator,
                    spec.name.as_bytes(),
                    spec.dtype.as_str().as_bytes(),
                    &shape_bytes,
                    &spec.length.to_be_bytes(),
                ],
            );
        }
        accumulator
    }
}

/// Parses the safetensors container format.
///
/// Layout is an 8-byte little-endian header length, that many bytes of JSON
/// describing each tensor, then the data segment. Every declared range is checked
/// against the segment: a header claiming bytes past the end, or a length that
/// disagrees with `shape × width`, is rejected rather than truncated, because a
/// tensor silently read short would commit to weights nobody shipped.
fn parse_safetensors(bytes: &[u8]) -> Result<Vec<Tensor>> {
    if bytes.len() < 8 {
        return Err(TvcError::MalformedTensorFile(format!(
            "file is {} bytes, too short to hold a header length",
            bytes.len()
        )));
    }
    let header_len = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")) as usize;
    let header_end = 8usize.checked_add(header_len).ok_or_else(|| {
        TvcError::MalformedTensorFile("header length overflows the address space".to_owned())
    })?;
    if header_end > bytes.len() {
        return Err(TvcError::MalformedTensorFile(format!(
            "header claims {header_len} bytes but only {} remain",
            bytes.len() - 8
        )));
    }

    let header: serde_json::Value = serde_json::from_slice(&bytes[8..header_end])
        .map_err(|error| TvcError::MalformedTensorFile(format!("header is not JSON: {error}")))?;
    let entries = header.as_object().ok_or_else(|| {
        TvcError::MalformedTensorFile("header is not a JSON object".to_owned())
    })?;

    let data = &bytes[header_end..];
    let mut tensors = Vec::new();

    for (name, spec) in entries {
        if name == "__metadata__" {
            continue;
        }
        let spec = spec.as_object().ok_or_else(|| {
            TvcError::MalformedTensorFile(format!("tensor {name}: entry is not an object"))
        })?;

        let dtype = Dtype::parse(
            spec.get("dtype")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    TvcError::MalformedTensorFile(format!("tensor {name}: missing dtype"))
                })?,
        )?;

        let shape = spec
            .get("shape")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| TvcError::MalformedTensorFile(format!("tensor {name}: missing shape")))?
            .iter()
            .map(|value| {
                value.as_u64().ok_or_else(|| {
                    TvcError::MalformedTensorFile(format!("tensor {name}: non-integer dimension"))
                })
            })
            .collect::<Result<Vec<u64>>>()?;

        let offsets = spec
            .get("data_offsets")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                TvcError::MalformedTensorFile(format!("tensor {name}: missing data_offsets"))
            })?;
        if offsets.len() != 2 {
            return Err(TvcError::MalformedTensorFile(format!(
                "tensor {name}: data_offsets must hold exactly two values"
            )));
        }
        let start = offsets[0].as_u64().ok_or_else(|| {
            TvcError::MalformedTensorFile(format!("tensor {name}: non-integer start offset"))
        })? as usize;
        let end = offsets[1].as_u64().ok_or_else(|| {
            TvcError::MalformedTensorFile(format!("tensor {name}: non-integer end offset"))
        })? as usize;

        if start > end || end > data.len() {
            return Err(TvcError::MalformedTensorFile(format!(
                "tensor {name}: range {start}..{end} is outside the {} byte data segment",
                data.len()
            )));
        }
        let expected = element_count(&shape)
            .checked_mul(dtype.width() as u128)
            .ok_or_else(|| {
                TvcError::MalformedTensorFile(format!("tensor {name}: shape overflows"))
            })?;
        if expected != (end - start) as u128 {
            return Err(TvcError::MalformedTensorFile(format!(
                "tensor {name}: shape needs {expected} bytes, range supplies {}",
                end - start
            )));
        }

        tensors.push(Tensor {
            name: name.clone(),
            dtype,
            shape,
            data: data[start..end].to_vec(),
        });
    }

    if tensors.is_empty() {
        return Err(TvcError::MalformedTensorFile(
            "header declares no tensors".to_owned(),
        ));
    }
    Ok(tensors)
}

// ---------------------------------------------------------------------------
// Scheme layer
// ---------------------------------------------------------------------------

/// Interface every vector commitment scheme in this crate satisfies.
///
/// Deliberately knows nothing above a `&[FieldElement]`. Everything
/// protocol-specific — the tensor manifest, the quantisation scale, the scheme
/// tag — lives in [`WeightCommitment`] instead, so a scheme with a different
/// commitment shape (a KZG `G1` point, a Pedersen point) drops in by defining
/// the associated types and nothing outside this module changes.
pub trait VectorCommitment {
    /// The scheme's own commitment: a Merkle root here, a group element for KZG.
    type Commitment: Clone + core::fmt::Debug + PartialEq + Eq;
    /// Evidence that one position of a committed vector holds a given value.
    type Proof: Clone + core::fmt::Debug;
    /// Setup material. Empty for hash-based schemes; an SRS for KZG.
    type PublicParams: Clone + core::fmt::Debug + Default;
    /// The scheme's failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Identifier recorded in [`WeightCommitment::scheme`].
    fn scheme() -> &'static str;

    /// Canonical bytes of a commitment, for binding into [`WeightCommitment`].
    fn commitment_bytes(commitment: &Self::Commitment) -> Vec<u8>;

    /// Commits to a vector of field elements.
    ///
    /// # Errors
    ///
    /// Scheme-defined; [`MerkleVectorCommitment`] rejects an empty vector.
    fn commit(
        params: &Self::PublicParams,
        vector: &[FieldElement],
    ) -> core::result::Result<Self::Commitment, Self::Error>;

    /// Produces an opening for one position.
    ///
    /// # Errors
    ///
    /// Scheme-defined; [`MerkleVectorCommitment`] rejects an out-of-range index.
    fn open(
        params: &Self::PublicParams,
        vector: &[FieldElement],
        index: usize,
    ) -> core::result::Result<Self::Proof, Self::Error>;

    /// Checks that `commitment` opens to `element` at `index`.
    ///
    /// Returns `Ok(false)` for a well-formed proof that simply does not verify,
    /// and `Err` only for input the scheme cannot evaluate at all.
    ///
    /// # Errors
    ///
    /// Scheme-defined.
    fn verify_opening(
        params: &Self::PublicParams,
        commitment: &Self::Commitment,
        index: usize,
        element: &FieldElement,
        proof: &Self::Proof,
    ) -> core::result::Result<bool, Self::Error>;
}

/// A Merkle root together with the vector length that fixes the tree's shape.
///
/// The length is part of the commitment rather than an argument to verification
/// because the tree's shape — and therefore which levels promote — is a function
/// of it. A verifier that did not know the length could not tell a canonical
/// path from a path with steps inserted or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleCommitment {
    /// Root of the tree.
    pub tree_root: [u8; 32],
    /// Number of leaves.
    pub length: u64,
}

/// Proof that a committed vector holds a given element at a given index.
///
/// Only the sibling hashes are carried. Direction is derived from the index and
/// the number of steps is derived from the length, so there is **exactly one**
/// accepting proof for any given fact. Carrying a direction bit per step, as an
/// earlier version did, let a caller vary the proof bytes without changing what
/// was proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleOpening {
    /// Sibling hashes from the leaf upwards, skipping promoted levels.
    pub siblings: Vec<[u8; 32]>,
}

/// SHA-256 Merkle tree over the quantised weight vector.
///
/// Levels are folded pairwise; when a level has an odd width the final node is
/// **promoted** to the next level unchanged rather than hashed against a copy of
/// itself. Duplicating the last node is the classic Bitcoin CVE-2012-2459 shape,
/// where two different leaf counts yield one root. Promotion avoids the
/// duplication, and [`MerkleCommitment::length`] fixes the shape so a verifier
/// knows at which levels a promotion must have occurred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MerkleVectorCommitment;

/// Setup material for [`MerkleVectorCommitment`]: there is none.
///
/// A hash-based commitment needs no trusted setup, which is the main thing it has
/// over KZG. The type exists so the trait can carry an SRS for schemes that do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoParams;

impl MerkleVectorCommitment {
    /// Hashes one leaf, binding the element to its position.
    ///
    /// Without the index, a vector holding the same value twice would produce
    /// identical leaves, and an opening for one position would prove the other.
    fn leaf(index: usize, element: &FieldElement) -> [u8; 32] {
        tagged_hash(
            DOMAIN_WEIGHT_LEAF,
            &[&(index as u64).to_be_bytes(), element.as_bytes()],
        )
    }

    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        tagged_hash(DOMAIN_WEIGHT_NODE, &[left, right])
    }
}

/// A committed vector that retains its tree, so openings are `O(log n)`.
///
/// Building the tree is `O(n)` and is done once. [`VectorCommitment::open`]
/// rebuilds it per call, which is the right shape for a one-shot opening and the
/// wrong one for a verifier auditing many positions; this type is for the latter.
#[derive(Clone, Debug)]
pub struct MerkleProver {
    /// Every level, leaves first, root last.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleProver {
    /// Builds the tree over a vector.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::EmptyWeights`] if the vector holds no elements.
    pub fn build(vector: &[FieldElement]) -> Result<Self> {
        if vector.is_empty() {
            return Err(TvcError::EmptyWeights);
        }

        let leaves: Vec<[u8; 32]> = vector
            .iter()
            .enumerate()
            .map(|(index, element)| MerkleVectorCommitment::leaf(index, element))
            .collect();

        let mut levels = vec![leaves];
        while levels.last().expect("non-empty").len() > 1 {
            let current = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut pairs = current.chunks_exact(2);
            for pair in &mut pairs {
                next.push(MerkleVectorCommitment::node(&pair[0], &pair[1]));
            }
            if let [promoted] = pairs.remainder() {
                next.push(*promoted);
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Whether the tree holds no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The scheme-level commitment this tree represents.
    pub fn commitment(&self) -> MerkleCommitment {
        MerkleCommitment {
            tree_root: *self
                .levels
                .last()
                .and_then(|top| top.first())
                .expect("non-empty"),
            length: self.len() as u64,
        }
    }

    /// Produces the canonical opening for one position.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::IndexOutOfRange`] if `index` is past the end.
    pub fn open(&self, index: usize) -> Result<MerkleOpening> {
        if index >= self.len() {
            return Err(TvcError::IndexOutOfRange {
                index,
                length: self.len(),
            });
        }

        let mut siblings = Vec::new();
        let mut position = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = position ^ 1;
            // A promoted node has no sibling at this level and emits no step.
            if sibling < level.len() {
                siblings.push(level[sibling]);
            }
            position /= 2;
        }
        Ok(MerkleOpening { siblings })
    }
}

impl VectorCommitment for MerkleVectorCommitment {
    type Commitment = MerkleCommitment;
    type Proof = MerkleOpening;
    type PublicParams = NoParams;
    type Error = TvcError;

    fn scheme() -> &'static str {
        MERKLE_SCHEME_TAG
    }

    fn commitment_bytes(commitment: &Self::Commitment) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&commitment.tree_root);
        bytes.extend_from_slice(&commitment.length.to_be_bytes());
        bytes
    }

    fn commit(_params: &NoParams, vector: &[FieldElement]) -> Result<MerkleCommitment> {
        Ok(MerkleProver::build(vector)?.commitment())
    }

    fn open(_params: &NoParams, vector: &[FieldElement], index: usize) -> Result<MerkleOpening> {
        MerkleProver::build(vector)?.open(index)
    }

    /// Walks the path, deriving both the direction and the expected number of
    /// steps from `index` and [`MerkleCommitment::length`].
    ///
    /// Recomputing the level widths `W_k = ⌈W_{k-1}/2⌉` is what makes promotion
    /// safe: the verifier knows exactly which levels must promote, so a path with
    /// a step inserted at a promoted level, or one removed at an unpromoted level,
    /// is rejected on step count rather than being hashed into some other root.
    fn verify_opening(
        _params: &NoParams,
        commitment: &MerkleCommitment,
        index: usize,
        element: &FieldElement,
        proof: &MerkleOpening,
    ) -> Result<bool> {
        if commitment.length == 0 || index as u64 >= commitment.length {
            return Ok(false);
        }

        let mut running = MerkleVectorCommitment::leaf(index, element);
        let mut position = index;
        let mut width = commitment.length as usize;
        let mut consumed = 0usize;

        while width > 1 {
            let sibling = position ^ 1;
            if sibling < width {
                let Some(hash) = proof.siblings.get(consumed) else {
                    return Ok(false); // path is shorter than the tree requires
                };
                running = if position % 2 == 1 {
                    MerkleVectorCommitment::node(hash, &running)
                } else {
                    MerkleVectorCommitment::node(&running, hash)
                };
                consumed += 1;
            }
            position /= 2;
            width = width.div_ceil(2);
        }

        if consumed != proof.siblings.len() {
            return Ok(false); // path carries steps the tree has no place for
        }
        Ok(running == commitment.tree_root)
    }
}

// ---------------------------------------------------------------------------
// Protocol layer
// ---------------------------------------------------------------------------

/// A published weight commitment `C`.
///
/// [`Self::root`] is the value that travels: it is what a publisher signs and
/// what the registry stores. It is **always 32 bytes**, because it is always a
/// tagged hash over the scheme's commitment rather than the scheme's commitment
/// itself — which is what lets the scheme change without touching
/// [`crate::signer`] or [`crate::registry`]. The remaining fields are the binding
/// inputs, carried so an auditor can recompute the root rather than trust it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightCommitment {
    /// Scheme that produced this commitment, for example [`MERKLE_SCHEME_TAG`].
    pub scheme: String,
    /// The 32-byte commitment `C`.
    pub root: [u8; 32],
    /// The underlying scheme's own commitment, canonically encoded.
    pub scheme_commitment: Vec<u8>,
    /// Number of field elements committed.
    pub length: u64,
    /// Fixed-point scale the weights were quantised at.
    pub fractional_bits: u32,
    /// Digest over the tensor manifest.
    pub manifest_digest: [u8; 32],
}

impl WeightCommitment {
    /// Binds a scheme commitment to the metadata that gives it meaning.
    pub fn bind(
        scheme: &str,
        scheme_commitment: Vec<u8>,
        length: u64,
        fractional_bits: u32,
        manifest_digest: [u8; 32],
    ) -> Self {
        Self {
            root: bind_root(
                scheme,
                &scheme_commitment,
                length,
                fractional_bits,
                &manifest_digest,
            ),
            scheme: scheme.to_owned(),
            scheme_commitment,
            length,
            fractional_bits,
            manifest_digest,
        }
    }

    /// Lowercase hex rendering of [`Self::root`].
    pub fn root_hex(&self) -> String {
        hex::encode(&self.root)
    }

    /// Recomputes the bound root from the carried inputs.
    ///
    /// An auditor calls this to confirm the published `C` really is the binding
    /// of the scheme commitment, length, scale and manifest it claims to be.
    pub fn rebind(&self) -> [u8; 32] {
        bind_root(
            &self.scheme,
            &self.scheme_commitment,
            self.length,
            self.fractional_bits,
            &self.manifest_digest,
        )
    }

    /// Whether [`Self::root`] matches its own binding inputs.
    pub fn is_self_consistent(&self) -> bool {
        self.rebind() == self.root
    }

    /// Recovers the Merkle scheme commitment, for verifying openings.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::OpeningRejected`] if this commitment was not produced
    /// by [`MerkleVectorCommitment`] or its encoding is malformed.
    pub fn merkle_commitment(&self) -> Result<MerkleCommitment> {
        if self.scheme != MERKLE_SCHEME_TAG || self.scheme_commitment.len() != 40 {
            return Err(TvcError::OpeningRejected);
        }
        let mut tree_root = [0u8; 32];
        tree_root.copy_from_slice(&self.scheme_commitment[..32]);
        let length = u64::from_be_bytes(
            self.scheme_commitment[32..]
                .try_into()
                .map_err(|_| TvcError::OpeningRejected)?,
        );
        if length != self.length {
            return Err(TvcError::OpeningRejected);
        }
        Ok(MerkleCommitment { tree_root, length })
    }
}

fn bind_root(
    scheme: &str,
    scheme_commitment: &[u8],
    length: u64,
    fractional_bits: u32,
    manifest_digest: &[u8; 32],
) -> [u8; 32] {
    tagged_hash(
        DOMAIN_WEIGHT_ROOT,
        &[
            scheme.as_bytes(),
            scheme_commitment,
            &length.to_be_bytes(),
            &fractional_bits.to_be_bytes(),
            manifest_digest,
        ],
    )
}

/// Commits to a weight vector with the default Merkle scheme.
///
/// # Errors
///
/// Returns [`TvcError::EmptyWeights`] if the vector holds no elements.
pub fn commit_weights(vector: &WeightVector) -> Result<WeightCommitment> {
    let commitment = MerkleVectorCommitment::commit(&NoParams, vector.elements())?;
    Ok(WeightCommitment::bind(
        MerkleVectorCommitment::scheme(),
        MerkleVectorCommitment::commitment_bytes(&commitment),
        vector.len() as u64,
        vector.fractional_bits(),
        vector.manifest_digest(),
    ))
}

/// Produces an opening for one weight.
///
/// # Errors
///
/// Returns [`TvcError::EmptyWeights`] or [`TvcError::IndexOutOfRange`].
pub fn open_weight(vector: &WeightVector, index: usize) -> Result<MerkleOpening> {
    MerkleProver::build(vector.elements())?.open(index)
}

/// Verifies an opening against a published weight commitment.
///
/// Checks the commitment's self-consistency as well as the path, so a `C` whose
/// carried inputs do not bind to it is rejected even if the path is genuine.
///
/// # Errors
///
/// Returns [`TvcError::OpeningRejected`] if either check fails.
pub fn verify_weight_opening(
    commitment: &WeightCommitment,
    index: u64,
    element: &FieldElement,
    opening: &MerkleOpening,
) -> Result<()> {
    if !commitment.is_self_consistent() {
        return Err(TvcError::OpeningRejected);
    }
    let scheme_commitment = commitment.merkle_commitment()?;
    let accepted = MerkleVectorCommitment::verify_opening(
        &NoParams,
        &scheme_commitment,
        index as usize,
        element,
        opening,
    )?;
    if accepted {
        Ok(())
    } else {
        Err(TvcError::OpeningRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_of(values: &[f32]) -> WeightVector {
        let tensor = Tensor::from_f32("layer.weight", vec![values.len() as u64], values).unwrap();
        WeightVector::from_tensors(vec![tensor], Quantizer::default()).unwrap()
    }

    #[test]
    fn negative_weights_map_below_the_modulus() {
        let element = FieldElement::from_i128(-1);
        let mut expected = FIELD_MODULUS;
        expected[31] -= 1;
        assert_eq!(element.as_bytes(), &expected);
        assert!(element.as_bytes() < &FIELD_MODULUS);
    }

    #[test]
    fn zero_and_negative_zero_quantise_identically() {
        assert_eq!(vector_of(&[0.0]).elements(), vector_of(&[-0.0]).elements());
    }

    #[test]
    fn quantisation_is_deterministic_and_scaled() {
        let quantizer = Quantizer::new(16).unwrap();
        assert_eq!(quantizer.quantize("t", 1.0).unwrap(), 65_536);
        assert_eq!(quantizer.quantize("t", -0.5).unwrap(), -32_768);
        assert!(quantizer.quantize("t", f64::NAN).is_err());
        assert!(quantizer.quantize("t", f64::INFINITY).is_err());
    }

    #[test]
    fn quantisation_rejects_values_past_the_exact_integer_bound() {
        let quantizer = Quantizer::new(16).unwrap();
        // 2^53 / 2^16 = 2^37 is the first magnitude whose scaling is inexact.
        let boundary = 2f64.powi(37);
        assert!(quantizer.quantize("t", boundary).is_err());
        assert!(quantizer.quantize("t", boundary - 1.0).is_ok());

        // The ceiling on the parameter is not reachable for large values: at 48
        // fractional bits only |v| < 32 survives, and that is a documented trap.
        let fine = Quantizer::new(48).unwrap();
        assert!(fine.quantize("t", 31.0).is_ok());
        assert!(fine.quantize("t", 32.0).is_err());
    }

    #[test]
    fn max_safe_fractional_bits_tracks_magnitude() {
        assert_eq!(Quantizer::max_safe_fractional_bits(0.5), 48);
        assert_eq!(Quantizer::max_safe_fractional_bits(1.0), 48);
        assert_eq!(Quantizer::max_safe_fractional_bits(1024.0), 42);
        assert_eq!(Quantizer::max_safe_fractional_bits(f64::NAN), 48);
        assert_eq!(Quantizer::max_safe_fractional_bits(2f64.powi(60)), 0);

        // Whatever it reports must actually be usable, and one more bit must not
        // be. This is the property; the arithmetic above is just illustration.
        for magnitude in [0.03125f64, 1.0, 3.7, 1024.0, 65_536.0, 2f64.powi(36)] {
            let scale = Quantizer::max_safe_fractional_bits(magnitude);
            assert!(
                Quantizer::new(scale).unwrap().quantize("t", magnitude).is_ok(),
                "reported scale {scale} unusable for {magnitude}"
            );
            if scale < Quantizer::MAX_FRACTIONAL_BITS {
                assert!(
                    Quantizer::new(scale + 1).unwrap().quantize("t", magnitude).is_err(),
                    "scale {} should have been too fine for {magnitude}",
                    scale + 1
                );
            }
        }
    }

    #[test]
    fn commitment_changes_when_one_weight_changes() {
        let baseline = commit_weights(&vector_of(&[1.0, 2.0, 3.0])).unwrap();
        let altered = commit_weights(&vector_of(&[1.0, 2.0, 3.5])).unwrap();
        assert_ne!(baseline.root, altered.root);
    }

    #[test]
    fn commitment_changes_when_tensors_are_reshaped() {
        let flat = Tensor::from_f32("w", vec![6], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        let square = Tensor::from_f32("w", vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        let flat = WeightVector::from_tensors(vec![flat], Quantizer::default()).unwrap();
        let square = WeightVector::from_tensors(vec![square], Quantizer::default()).unwrap();

        assert_eq!(flat.elements(), square.elements(), "same numbers");
        assert_ne!(
            commit_weights(&flat).unwrap().root,
            commit_weights(&square).unwrap().root,
            "shape must be bound into the commitment"
        );
    }

    #[test]
    fn commitment_changes_when_a_tensor_is_renamed() {
        let original = Tensor::from_f32("encoder.w", vec![2], &[1.0, 2.0]).unwrap();
        let renamed = Tensor::from_f32("decoder.w", vec![2], &[1.0, 2.0]).unwrap();
        assert_ne!(
            commit_weights(&WeightVector::from_tensors(vec![original], Quantizer::default()).unwrap())
                .unwrap()
                .root,
            commit_weights(&WeightVector::from_tensors(vec![renamed], Quantizer::default()).unwrap())
                .unwrap()
                .root
        );
    }

    #[test]
    fn commitment_changes_with_the_quantisation_scale() {
        let tensor = Tensor::from_f32("w", vec![2], &[1.0, 2.0]).unwrap();
        let coarse =
            WeightVector::from_tensors(vec![tensor.clone()], Quantizer::new(8).unwrap()).unwrap();
        let fine = WeightVector::from_tensors(vec![tensor], Quantizer::new(24).unwrap()).unwrap();
        assert_ne!(
            commit_weights(&coarse).unwrap().root,
            commit_weights(&fine).unwrap().root
        );
    }

    #[test]
    fn tensor_order_does_not_depend_on_input_order() {
        let a = Tensor::from_f32("a.w", vec![1], &[1.0]).unwrap();
        let b = Tensor::from_f32("b.w", vec![1], &[2.0]).unwrap();
        let forward = WeightVector::from_tensors(vec![a.clone(), b.clone()], Quantizer::default())
            .unwrap();
        let reverse = WeightVector::from_tensors(vec![b, a], Quantizer::default()).unwrap();
        assert_eq!(
            commit_weights(&forward).unwrap().root,
            commit_weights(&reverse).unwrap().root
        );
    }

    #[test]
    fn empty_vectors_are_rejected() {
        let empty = WeightVector {
            elements: Vec::new(),
            manifest: Vec::new(),
            fractional_bits: 16,
        };
        assert_eq!(commit_weights(&empty), Err(TvcError::EmptyWeights));
    }

    #[test]
    fn openings_verify_at_every_index_for_odd_and_even_widths() {
        // Widths through 17 exercise promotion at several levels at once.
        for width in 1..=17usize {
            let values: Vec<f32> = (0..width).map(|index| index as f32 * 0.25).collect();
            let vector = vector_of(&values);
            let commitment = commit_weights(&vector).unwrap();
            for index in 0..width {
                let opening = open_weight(&vector, index).unwrap();
                assert_eq!(
                    verify_weight_opening(
                        &commitment,
                        index as u64,
                        &vector.elements()[index],
                        &opening
                    ),
                    Ok(()),
                    "width {width}, index {index}"
                );
            }
        }
    }

    #[test]
    fn the_cached_prover_agrees_with_the_one_shot_path() {
        let vector = vector_of(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let prover = MerkleProver::build(vector.elements()).unwrap();
        assert_eq!(
            prover.commitment(),
            MerkleVectorCommitment::commit(&NoParams, vector.elements()).unwrap()
        );
        for index in 0..vector.len() {
            assert_eq!(
                prover.open(index).unwrap(),
                MerkleVectorCommitment::open(&NoParams, vector.elements(), index).unwrap()
            );
        }
    }

    #[test]
    fn an_opening_cannot_be_moved_to_another_index() {
        let vector = vector_of(&[7.0, 7.0, 7.0, 7.0]);
        let commitment = commit_weights(&vector).unwrap();
        let opening = open_weight(&vector, 0).unwrap();
        assert_eq!(
            verify_weight_opening(&commitment, 1, &vector.elements()[1], &opening),
            Err(TvcError::OpeningRejected),
            "identical values must not share a leaf"
        );
    }

    #[test]
    fn a_forged_element_is_rejected() {
        let vector = vector_of(&[1.0, 2.0, 3.0, 4.0]);
        let commitment = commit_weights(&vector).unwrap();
        let opening = open_weight(&vector, 2).unwrap();
        assert_eq!(
            verify_weight_opening(&commitment, 2, &FieldElement::from_i128(999), &opening),
            Err(TvcError::OpeningRejected)
        );
    }

    #[test]
    fn a_path_with_a_step_removed_is_rejected() {
        let vector = vector_of(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
        let commitment = commit_weights(&vector).unwrap();
        let mut opening = open_weight(&vector, 3).unwrap();
        opening.siblings.pop();
        assert_eq!(
            verify_weight_opening(&commitment, 3, &vector.elements()[3], &opening),
            Err(TvcError::OpeningRejected)
        );
    }

    #[test]
    fn a_path_with_a_step_appended_is_rejected() {
        // The tail element of an odd-width tree promotes, so a naive verifier
        // that trusted the supplied path length would accept an extra step here.
        let vector = vector_of(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let commitment = commit_weights(&vector).unwrap();
        let mut opening = open_weight(&vector, 4).unwrap();
        opening.siblings.push([0xab; 32]);
        assert_eq!(
            verify_weight_opening(&commitment, 4, &vector.elements()[4], &opening),
            Err(TvcError::OpeningRejected)
        );
    }

    #[test]
    fn a_promoted_tail_opening_is_canonical() {
        // Width 5: index 4 promotes at level 0 and level 1, so its canonical path
        // has exactly one step. Anything else must be refused.
        let vector = vector_of(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let commitment = commit_weights(&vector).unwrap();
        let opening = open_weight(&vector, 4).unwrap();
        assert_eq!(opening.siblings.len(), 1);
        assert_eq!(
            verify_weight_opening(&commitment, 4, &vector.elements()[4], &opening),
            Ok(())
        );
    }

    #[test]
    fn a_tampered_binding_is_rejected() {
        let vector = vector_of(&[1.0, 2.0, 3.0]);
        let mut commitment = commit_weights(&vector).unwrap();
        let opening = open_weight(&vector, 1).unwrap();
        commitment.length = 99;
        assert!(!commitment.is_self_consistent());
        assert_eq!(
            verify_weight_opening(&commitment, 1, &vector.elements()[1], &opening),
            Err(TvcError::OpeningRejected)
        );
    }

    #[test]
    fn an_out_of_range_index_is_refused() {
        let vector = vector_of(&[1.0, 2.0]);
        assert_eq!(
            open_weight(&vector, 2),
            Err(TvcError::IndexOutOfRange {
                index: 2,
                length: 2
            })
        );
        let commitment = commit_weights(&vector).unwrap();
        let opening = open_weight(&vector, 1).unwrap();
        assert_eq!(
            verify_weight_opening(&commitment, 2, &vector.elements()[1], &opening),
            Err(TvcError::OpeningRejected)
        );
    }

    #[test]
    fn the_bound_root_is_32_bytes_whatever_the_scheme_commitment_is() {
        // The property that keeps signer.rs and registry.rs scheme-agnostic.
        let short = WeightCommitment::bind("toy/1", vec![0u8; 1], 1, 16, [0u8; 32]);
        let long = WeightCommitment::bind("toy/1", vec![0u8; 96], 1, 16, [0u8; 32]);
        assert_eq!(short.root.len(), 32);
        assert_eq!(long.root.len(), 32);
        assert_ne!(short.root, long.root);
        assert!(short.is_self_consistent() && long.is_self_consistent());
    }

    #[test]
    fn a_foreign_scheme_cannot_be_opened_as_merkle() {
        let foreign = WeightCommitment::bind("kzg-bn254/1", vec![0u8; 32], 4, 16, [0u8; 32]);
        assert_eq!(foreign.merkle_commitment(), Err(TvcError::OpeningRejected));
    }

    #[test]
    fn half_precision_widens_correctly() {
        assert_eq!(f16_to_f32(0x3c00), 1.0);
        assert_eq!(f16_to_f32(0xc000), -2.0);
        assert_eq!(f16_to_f32(0x0000), 0.0);
        assert_eq!(f16_to_f32(0x0001), 2f32.powi(-24));
        assert!(f16_to_f32(0x7e00).is_nan());
        assert_eq!(bf16_to_f32(0x3f80), 1.0);
        assert_eq!(bf16_to_f32(0xc000), -2.0);
    }

    #[test]
    fn bfloat16_widening_is_exact_including_subnormals() {
        // bf16 is the high half of an f32, so the shift must round-trip exactly.
        for bits in [0x0001u16, 0x0080, 0x7f80, 0xff80, 0x7fc0, 0x8000] {
            let widened = bf16_to_f32(bits);
            assert_eq!(
                (widened.to_bits() >> 16) as u16,
                bits,
                "bf16 {bits:#06x} did not survive widening"
            );
        }
        assert!(bf16_to_f32(0x0001).is_subnormal());
        assert!(bf16_to_f32(0x7f80).is_infinite());
        assert!(bf16_to_f32(0x7fc0).is_nan());
    }

    #[test]
    fn subnormal_inputs_quantise_to_zero_at_every_scale() {
        // The reason flush-to-zero cannot change a commitment: a subnormal is
        // many orders of magnitude below half a step at any supported scale, so
        // it rounds to zero whether or not the hardware flushed it first.
        for bits in [1u64, 8] {
            let quantizer = Quantizer::new(Quantizer::MAX_FRACTIONAL_BITS).unwrap();
            let subnormal = f64::from_bits(bits);
            assert!(subnormal.is_subnormal());
            assert_eq!(quantizer.quantize("t", subnormal).unwrap(), 0);
            assert_eq!(quantizer.quantize("t", -subnormal).unwrap(), 0);
            assert_eq!(quantizer.quantize("t", 0.0).unwrap(), 0);
        }
    }

    /// Builds a minimal safetensors buffer holding one F32 tensor.
    fn safetensors_fixture(shape: &str, byte_len: usize) -> Vec<u8> {
        let header = format!(
            r#"{{"w":{{"dtype":"F32","shape":{shape},"data_offsets":[0,{byte_len}]}}}}"#
        );
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(header.as_bytes());
        for index in 0..byte_len / 4 {
            bytes.extend_from_slice(&(index as f32).to_le_bytes());
        }
        bytes
    }

    #[test]
    fn safetensors_roundtrips_through_the_quantiser() {
        let bytes = safetensors_fixture("[4]", 16);
        let vector = WeightVector::from_safetensors_bytes(&bytes, Quantizer::default()).unwrap();
        assert_eq!(vector.len(), 4);
        assert_eq!(vector.manifest()[0].shape, vec![4]);
        assert_eq!(vector.elements()[2], FieldElement::from_i128(2 * 65_536));
        assert!(commit_weights(&vector).unwrap().is_self_consistent());
    }

    #[test]
    fn safetensors_rejects_a_shape_that_disagrees_with_its_range() {
        let bytes = safetensors_fixture("[5]", 16);
        assert!(matches!(
            WeightVector::from_safetensors_bytes(&bytes, Quantizer::default()),
            Err(TvcError::MalformedTensorFile(_))
        ));
    }

    #[test]
    fn safetensors_rejects_a_truncated_file() {
        let bytes = safetensors_fixture("[4]", 16);
        let truncated = &bytes[..bytes.len() - 4];
        assert!(matches!(
            WeightVector::from_safetensors_bytes(truncated, Quantizer::default()),
            Err(TvcError::MalformedTensorFile(_))
        ));
        assert!(matches!(
            WeightVector::from_safetensors_bytes(&[0u8; 3], Quantizer::default()),
            Err(TvcError::MalformedTensorFile(_))
        ));
    }

    #[test]
    fn safetensors_rejects_an_oversized_header_length() {
        let mut bytes = safetensors_fixture("[4]", 16);
        bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            WeightVector::from_safetensors_bytes(&bytes, Quantizer::default()),
            Err(TvcError::MalformedTensorFile(_))
        ));
    }

    #[test]
    fn safetensors_skips_the_metadata_key() {
        let header = r#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&2.0f32.to_le_bytes());

        let vector = WeightVector::from_safetensors_bytes(&bytes, Quantizer::default()).unwrap();
        assert_eq!(vector.len(), 2);
        assert_eq!(vector.manifest().len(), 1);
    }

    #[test]
    fn unsupported_dtypes_are_named_not_guessed() {
        assert_eq!(
            Dtype::parse("BOOL"),
            Err(TvcError::UnsupportedDtype("BOOL".to_owned()))
        );
    }

    #[test]
    fn non_canonical_field_elements_are_rejected() {
        assert!(FieldElement::from_canonical_bytes(FIELD_MODULUS).is_err());
        assert!(FieldElement::from_canonical_bytes([0u8; 32]).is_ok());
    }
}
