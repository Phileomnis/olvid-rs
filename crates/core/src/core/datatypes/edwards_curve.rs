use num::BigInt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EdwardsCurveError {
    #[error("Computation error")]
    Computation,
    #[error("Coordinates computation error")]
    Coordinates,
    #[error("Given point not on curve")]
    PointNotOnCurve,
    #[error("Technical error")]
    Techninal,
    #[error("Unknwon algo implem byte id {0}")]
    UnknownAlgoImplemByteId(u8)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurvePoint {
    pub x: BigInt,
    pub y: BigInt
}

impl CurvePoint {
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Self { x, y }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurveType {
    MDC,
    Curve25519
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdwardsCurve {
    pub curve_type: CurveType,
    pub p: BigInt,
    pub d: BigInt,
    pub G: CurvePoint,
    pub q: BigInt,
    pub nu: BigInt,
    pub tonneli_s: u8,
    pub tonelli_non_qr: BigInt,
    pub tonelli_t: BigInt
}

impl EdwardsCurve {
    pub fn algo_implem_id(&self) -> u8 {
        match self.curve_type {
            CurveType::MDC => 0x00,
            CurveType::Curve25519 => 0x01,
        }
    }
}