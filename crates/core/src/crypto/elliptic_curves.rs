use std::str::FromStr;

use crypto_bigint::{modular::{BoxedMontyForm, BoxedMontyParams, MontyForm}, subtle::Choice, BoxedUint, CheckedSub, ConstChoice, DecodeError, Monty, Odd, Pow};
use num::{bigint::ToBigInt, BigInt, FromPrimitive, Num, One, Zero};
use thiserror::Error;

use crate::core::{asymmetric::edwards_key::{ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519, ALGO_IMPLEM_BYTE_ID_CURVE_MDC}, edwards_curve::{CurvePoint, CurveType, EdwardsCurve, EdwardsCurveError}};

use super::prng::PRNG;

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct CurvePoint {
//     x: BigInt,
//     y: BigInt
// }

// impl CurvePoint {
//     pub fn new(x: BigInt, y: BigInt) -> Self {
//         Self { x, y }
//     }
// }
// pub struct EdwardsCurve {
//     p: BigInt,
//     d: BigInt,
//     G: CurvePoint,
//     q: BigInt,
//     nu: BigInt,
//     tonneli_s: u8,
//     tonelli_non_qr: BigInt,
//     tonelli_t: BigInt
// }

impl EdwardsCurve {
    pub fn curve_from_algo_implem_byte_id(algo_implem_byte_id: u8) -> Result<EdwardsCurve, EdwardsCurveError> {
        if algo_implem_byte_id == ALGO_IMPLEM_BYTE_ID_CURVE_MDC {
            return Ok(EdwardsCurve::new_mdc()?);
        }

        if algo_implem_byte_id == ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519 {
            return Ok(EdwardsCurve::new_curve25519()?);
        }

        Err(EdwardsCurveError::UnknownAlgoImplemByteId(algo_implem_byte_id))
    }

    pub fn algo_implem_byte_id_from_curve(curve: &EdwardsCurve) -> Result<u8, EdwardsCurveError> {
        if curve.curve_type == CurveType::MDC {
            return Ok(ALGO_IMPLEM_BYTE_ID_CURVE_MDC);
        }

        return Ok(ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519);
    }

    pub fn is_on_curve(&self, x: &BigInt, y: &BigInt) -> bool {
        let x2 = &x.pow(2);
        let y2 = &y.pow(2);

        let is_on_curve = (x2 + y2) %& self.p == (1 + &self.d * x2 * y2) % &self.p;
        is_on_curve
    }

    pub fn x_coordinates_from_y(&self, y: &BigInt) -> Result<BigInt, EdwardsCurveError> {
        let one = &BigInt::one();
        let two = &BigInt::from(2);

        let y_2 = y.modpow(two, &self.p);
        let x_2 = ((one - &y_2) * (one - &self.d * &y_2).modinv(&self.p).ok_or(EdwardsCurveError::Computation)?).modpow(one, &self.p);

        let p_minus_one_div_two = (&self.p - one) / two;
        if &x_2.modpow(&p_minus_one_div_two, &self.p) != one {
            return Err(EdwardsCurveError::Coordinates);
        }

        if self.p.bit(1) {
            let four = &BigInt::from(4);
            let p_plus_one_div_four = (&self.p + one) / four;
            return Ok(x_2.modpow(&p_plus_one_div_four, &self.p));
        }

        let mut e = BigInt::zero();
        for i in 1..self.tonneli_s {
            let tmp = (self.tonelli_non_qr.modpow(&e, &self.p) * &x_2).modpow(&(&p_minus_one_div_two / &BigInt::from(2u8.pow(i.into()))), &self.p);
            if &tmp != one {
                e = &e + &two.pow(i.into());
            }
        }

        let result = self.tonelli_non_qr.modpow(&((&self.tonelli_t * &e) / two), &self.p) * (&x_2.modpow(&((&self.tonelli_t + one) / two), &self.p)) % &self.p;
        Ok(result)
    }

    pub fn scalar_multiplication(&self, n: &BigInt, y: &BigInt) -> Result<BigInt, EdwardsCurveError> {
        let zero = &BigInt::zero();
        let one = &BigInt::one();
        let two = &BigInt::from(2);

        if n == zero || y == one {
            return Ok(one.clone())
        }

        if y == &(-one) {
            return Ok(1 - 2 * (n % 2))
        }

        let c = (one - &self.d).modinv(&self.p).ok_or(EdwardsCurveError::Computation)?;
        let u_P = (one + y) % &self.p;
        let w_P = (one - y) % &self.p;
        let mut u_Q = one.clone();
        let mut w_Q = zero.clone();
        let mut u_R = u_P.clone();
        let mut w_R = w_P.clone();

        let l = n.bits();
        for i in (0..l).rev() {
            let t_1 = ((&u_Q - &w_Q) * (&u_R + &w_R)) % &self.p;
            let t_2 = ((&u_Q + &w_Q) * (&u_R - &w_R)) % &self.p;
            let u_QR = (&w_P * (&t_1 + &t_2).modpow(&two, &self.p)) % &self.p;
            let w_QR = (&u_P * (&t_1 - &t_2).modpow(&two, &self.p)) % &self.p;

            if n.bit(i) == false {
                let t_3 = (&u_Q + &w_Q).modpow(&two, &self.p);
                let t_4 = (&u_Q - &w_Q).modpow(&two, &self.p);
                let t_5 = (&t_3 - &t_4) % &self.p;
                let u_2Q = (&t_3 * &t_4) % &self.p;
                let w_2Q = (&t_5 * (&t_4 + &c * &t_5)) % &self.p;
                u_Q = u_2Q;
                w_Q = w_2Q;
                u_R = u_QR;
                w_R = w_QR;
            } else {
                let t_3 = (&u_R + &w_R).modpow(&two, &self.p);
                let t_4 = (&u_R - &w_R).modpow(&two, &self.p);
                let t_5 = (&t_3 - &t_4) % &self.p;
                let u_2R = (&t_3 * &t_4) % &self.p;
                let w_2R = (&t_5 * (&t_4 + (&c * &t_5))) % &self.p;
                u_Q = u_QR;
                w_Q = w_QR;
                u_R = u_2R;
                w_R = w_2R;
            }
        }
        let result = ((&u_Q - &w_Q) * ((&u_Q + &w_Q).modinv(&self.p)).ok_or(EdwardsCurveError::Computation)?).modpow(&one, &self.p);

        Ok(result)
    }

    pub fn point_addition(&self, p_1: &CurvePoint, p_2: &CurvePoint) -> Result<CurvePoint, EdwardsCurveError> {
        let t = (&self.d * &p_1.x * &p_2.x * &p_1.y * &p_2.y) % &self.p;
        let one = BigInt::one();
        let mut z = (&one + &t).modinv(&self.p).ok_or(EdwardsCurveError::Computation)? % &self.p;
        let x = &z * (&p_1.x * &p_2.y + &p_1.y * &p_2.x) % &self.p;
        z = (&one - &t).modinv(&self.p).ok_or(EdwardsCurveError::Computation)? % &self.p;
        let y = (&z * (&p_1.y * &p_2.y - &p_1.x * &p_2.x) % &self.p).modpow(&one, &self.p);
        Ok(CurvePoint::new(x, y))
    }

    pub fn scalar_multiplication_with_x(&self, n: &BigInt, p: &CurvePoint) -> Result<CurvePoint, EdwardsCurveError> {
        if !self.is_on_curve(&p.x, &p.y) {
            return Err(EdwardsCurveError::PointNotOnCurve);
        }

        let zero = &BigInt::zero();
        let one = &BigInt::one();

        if n == zero || &p.y == one {
            return Ok(CurvePoint::new(zero.clone(), one.clone()));
        }

        let two = &BigInt::from_u8(2).ok_or(EdwardsCurveError::Techninal)?;
        if p.y == -one {
            let y = one - two * (n % two);
            return Ok(CurvePoint::new(zero.clone(), y));
        }

        let mut p_1 = CurvePoint::new(zero.clone(), one.clone());
        let mut p_2 = CurvePoint::new(p.x.clone(), p.y.clone());

        let l = n.bits();
        for i in (0..l).rev() {
            if !n.bit(i) {
                p_2 = self.point_addition(&p_1, &p_2)?;
                p_1 = self.point_addition(&p_1, &p_1)?;
            } else {
                p_1 = self.point_addition(&p_1, &p_2)?;
                p_2 = self.point_addition(&p_2, &p_2)?;
            }
        }

        Ok(p_1)
    }

    pub fn mul_add(&self, a: &BigInt, p_1: &CurvePoint, b: &BigInt, p_2: (Option<&BigInt>, &BigInt)) -> Result<(CurvePoint, CurvePoint), EdwardsCurveError> {
        let p_3 = self.scalar_multiplication_with_x(a, p_1)?;
        if p_2.0.is_some() {
            let p_2 = CurvePoint::new(p_2.0.unwrap().clone(), p_2.1.clone());
            let p_4 = self.scalar_multiplication_with_x(b, &p_2)?;
            let p = self.point_addition(&p_3, &p_4)?;
            return Ok((p.clone(), p.clone()));
        }

        let y_4 = self.scalar_multiplication(b, &p_2.1)?;
        let x_4 = self.x_coordinates_from_y(&y_4)?;
        let p_4a = CurvePoint::new(x_4.clone(), y_4.clone());
        let p_4b = CurvePoint::new(&self.p - &x_4, y_4.clone());
        
        Ok((self.point_addition(&p_3, &p_4a)?, self.point_addition(&p_3, &p_4b)?))
    }

    pub fn new_mdc() -> Result<Self, EdwardsCurveError> {
        let p = BigInt::from_str("109112363276961190442711090369149551676330307646118204517771511330536253156371").map_err(|_| EdwardsCurveError::Techninal)?;
        let d = BigInt::from_str("39384817741350628573161184301225915800358770588933756071948264625804612259721").map_err(|_| EdwardsCurveError::Techninal)?;

        let g_x = BigInt::from_str("82549803222202399340024462032964942512025856818700414254726364205096731424315").map_err(|_| EdwardsCurveError::Techninal)?;
        let g_y = BigInt::from_str("91549545637415734422658288799119041756378259523097147807813396915125932811445").map_err(|_| EdwardsCurveError::Techninal)?;

        let q = BigInt::from_str("27278090819240297610677772592287387918930509574048068887630978293185521973243").map_err(|_| EdwardsCurveError::Techninal)?;

        let nu = BigInt::from_i8(4).ok_or(EdwardsCurveError::Techninal)?;

        let tonelli_non_qr = BigInt::from(2);
        let tonelli_t = &p / BigInt::from(2);

        Ok(Self { p, d, G: CurvePoint::new(g_x, g_y), q, nu, tonneli_s: 1, tonelli_non_qr, tonelli_t, curve_type: CurveType::MDC })
    }

    pub fn new_curve25519() -> Result<Self, EdwardsCurveError> {
        let p = BigInt::from_str_radix("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).map_err(|_| EdwardsCurveError::Techninal)?;
        let d = BigInt::from_str("20800338683988658368647408995589388737092878452977063003340006470870624536394").map_err(|_| EdwardsCurveError::Techninal)?;

        let g_x = BigInt::from_str("9771384041963202563870679428059935816164187996444183106833894008023910952347").map_err(|_| EdwardsCurveError::Techninal)?;
        let g_y = BigInt::from_str("46316835694926478169428394003475163141307993866256225615783033603165251855960").map_err(|_| EdwardsCurveError::Techninal)?;

        let q = BigInt::from_str("7237005577332262213973186563042994240857116359379907606001950938285454250989").map_err(|_| EdwardsCurveError::Techninal)?;

        let nu = BigInt::from_i8(8).ok_or(EdwardsCurveError::Techninal)?;

        let tonelli_non_qr = BigInt::from(2);
        let tonelli_t = &p / BigInt::from(4);

        Ok(Self { p, d, G: CurvePoint::new(g_x, g_y), q, nu, tonneli_s: 2, tonelli_non_qr, tonelli_t, curve_type: CurveType::Curve25519 })
    }

    // pub fn generate_random_scalar_and_point(&self, prng: &mut impl PRNG) -> Result<(BigInt, CurvePoint), EdwardsCurveError> {
    //     let two = &BigInt::from(2);
    //     let lambda = two + prng.big_int(&(&self.q - two)).map_err(|_| EdwardsCurveError::Computation)?;
    //     let q = self.scalar_multiplication_with_x(&lambda, &self.G)?;
    //     Ok((lambda, q))
    // }

    pub fn generate_random_scalar_and_point(&self, prng: &mut dyn PRNG) -> Result<(BigInt, CurvePoint), EdwardsCurveError> {
        let mut a = prng.big_int(&self.q).unwrap();
        while a == BigInt::one() || a == BigInt::zero() {
            a = prng.big_int(&self.q).unwrap();
        }
        let aG = self.scalar_multiplication_with_x(&a, &self.G)?;
        Ok((a, aG))
    }

    // pub fn curve_from_algo_implem_byte_id(algo_implem_byte_id: u8) -> Result<Self, EdwardsCurveError> {
    //     if algo_implem_byte_id == ALGO_IMPLEM_BYTE_ID_CURVE_MDC {
    //         return Ok(Self::new_mdc()?);
    //     }

    //     if algo_implem_byte_id == ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519 {
    //         return Ok(Self::new_curve25519()?);
    //     }

    //     return Err(EdwardsCurveError::UnknownAlgoImplemByteId);
    // }

    pub fn is_low_order_point(&self, ay: &BigInt) -> Result<bool, EdwardsCurveError> {
        return Ok(self.scalar_multiplication(&self.nu, &ay)?.eq(&BigInt::one()));
    }
 }

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crypto_bigint::BoxedUint;
    use num::BigInt;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use serde::{Deserialize, Serialize};

    use crate::crypto::{elliptic_curves::CurvePoint, utils::tests::{get_test_vectors, TestBigInteger}};

    use super::EdwardsCurve;

    #[derive(Deserialize)]
    struct TestIsOnCurve {
        x: TestBigInteger,
        x2: TestBigInteger,
        y: TestBigInteger
    }

    #[test]
    fn is_on_curve_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestIsOnCurve>("TestVectorsIsOnCurveMDC.json");
        for test_case in test_cases {
            let x = BigInt::from_str(&test_case.x.0).unwrap();
            let x2 = BigInt::from_str(&test_case.x2.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();

            assert!(curve.is_on_curve(&x, &y));
            assert!(!curve.is_on_curve(&x2, &y));
        }
    }

    #[test]
    fn is_on_curve_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestIsOnCurve>("TestVectorsIsOnCurveCurve25519.json");
        for test_case in test_cases {
            let x = BigInt::from_str(&test_case.x.0).unwrap();
            let x2 = BigInt::from_str(&test_case.x2.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();

            assert!(curve.is_on_curve(&x, &y));
            assert!(!curve.is_on_curve(&x2, &y));
        }
    }

    fn test_x_coordinates_from_y(curve: &EdwardsCurve, test_cases: &[TestIsOnCurve]) {
        test_cases.par_iter().for_each(|test_case| {
            let x = BigInt::from_str(&test_case.x.0).unwrap();
            let x2 = BigInt::from_str(&test_case.x2.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();

            let computed_x2 = curve.x_coordinates_from_y(&y).unwrap();
            assert!(&x == &computed_x2 || &(&curve.p - &x) == &computed_x2);
        });
    }

    #[test]
    fn x_coordinates_from_y_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestIsOnCurve>("TestVectorsIsOnCurveMDC.json");

        test_x_coordinates_from_y(&curve, &test_cases);
    }

    #[test]
    fn x_coordinates_from_y_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestIsOnCurve>("TestVectorsIsOnCurveCurve25519.json");

        test_x_coordinates_from_y(&curve, &test_cases);
    }

    #[derive(Deserialize)]
    struct TestScalarMultiplication {
        n: TestBigInteger,
        ny: TestBigInteger,
        y: TestBigInteger
    }

    #[test]
    fn scalar_multiplication_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestScalarMultiplication>("TestVectorsScalarMultiplicationMDC.json");

        test_cases.par_iter().for_each(|test_case| {
            let n = BigInt::from_str(&test_case.n.0).unwrap();
            let ny = BigInt::from_str(&test_case.ny.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();

            let computed_ny = curve.scalar_multiplication(&n, &y).unwrap();
            assert_eq!(ny, computed_ny);
        });
    }

    #[test]
    fn scalar_multiplication_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestScalarMultiplication>("TestVectorsScalarMultiplicationCurve25519.json");

        test_cases.par_iter().for_each(|test_case| {
            let n = BigInt::from_str(&test_case.n.0).unwrap();
            let ny = BigInt::from_str(&test_case.ny.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();

            let computed_ny = curve.scalar_multiplication(&n, &y).unwrap();
            assert_eq!(ny, computed_ny);
        });
    }

    #[derive(Deserialize)]
    struct TestPointAddition {
        x: String,
        x2: String,
        x3: String,
        y: String,
        y2: String,
        y3: String
    }

    fn test_point_addtion(curve: &EdwardsCurve, test_cases: &[TestPointAddition]) {
        test_cases.par_iter().for_each(|test_case| {
            let x = BigInt::from_str(&test_case.x).unwrap();
            let x2 = BigInt::from_str(&test_case.x2).unwrap();
            let x3 = BigInt::from_str(&test_case.x3).unwrap();
            let y = BigInt::from_str(&test_case.y).unwrap();
            let y2 = BigInt::from_str(&test_case.y2).unwrap();
            let y3 = BigInt::from_str(&test_case.y3).unwrap();

            let p = CurvePoint::new(x, y);
            let q = CurvePoint::new(x2, y2);
            let r = CurvePoint::new(x3, y3);

            let r2 = curve.point_addition(&p, &q).unwrap();
            assert_eq!(r2, r);
        });
    }

    #[test]
    fn point_addition_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestPointAddition>("TestVectorsPointAdditionMDC.json");

        test_point_addtion(&curve, &test_cases);
    }

    #[test]
    fn point_addition_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestPointAddition>("TestVectorsPointAdditionCurve25519.json");
        
        test_point_addtion(&curve, &test_cases);
    }

    #[derive(Deserialize)]
    struct TestScalarMultiplicationWithX {
        n: TestBigInteger,
        x: TestBigInteger,
        x2: TestBigInteger,
        y: TestBigInteger,
        y2: TestBigInteger,
    }

    fn test_scalar_multiplication_with_x(curve: &EdwardsCurve, test_cases: &[TestScalarMultiplicationWithX]) {
        test_cases.par_iter().for_each(|test_case| {
            let n = BigInt::from_str(&test_case.n.0).unwrap();
            let x = BigInt::from_str(&test_case.x.0).unwrap();
            let x2 = BigInt::from_str(&test_case.x2.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();
            let y2 = BigInt::from_str(&test_case.y2.0).unwrap();

            let p = CurvePoint::new(x, y);
            let q = CurvePoint::new(x2, y2);

            let q2 = curve.scalar_multiplication_with_x(&n, &p).unwrap();

            assert_eq!(q2, q);
        });
    }

    #[test]
    fn scalar_multiplication_with_x_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestScalarMultiplicationWithX>("TestVectorsScalarMultiplicationWithXMDC.json");
        
        test_scalar_multiplication_with_x(&curve, &test_cases);
    }

    #[test]
    fn scalar_multiplication_with_x_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestScalarMultiplicationWithX>("TestVectorsScalarMultiplicationWithXCurve25519.json");
        
        test_scalar_multiplication_with_x(&curve, &test_cases);
    }

    #[derive(Deserialize)]
    struct TestMulAdd {
        a: TestBigInteger,
        b: TestBigInteger,
        x: TestBigInteger,
        x2: TestBigInteger,
        x3: TestBigInteger,
        x4: TestBigInteger,
        x5: TestBigInteger,
        y: TestBigInteger,
        y2: TestBigInteger,
        y3: TestBigInteger,
        y4: TestBigInteger,
        y5: TestBigInteger,
    }

    fn test_mul_add(curve: &EdwardsCurve, test_cases: &[TestMulAdd]) {
        test_cases.par_iter().for_each(|test_case| {
            let a = BigInt::from_str(&test_case.a.0).unwrap();
            let b = BigInt::from_str(&test_case.b.0).unwrap();
            let x = BigInt::from_str(&test_case.x.0).unwrap();
            let x2 = BigInt::from_str(&test_case.x2.0).unwrap();
            let x3 = BigInt::from_str(&test_case.x3.0).unwrap();
            let x4 = BigInt::from_str(&test_case.x4.0).unwrap();
            let x5 = BigInt::from_str(&test_case.x5.0).unwrap();
            let y = BigInt::from_str(&test_case.y.0).unwrap();
            let y2 = BigInt::from_str(&test_case.y2.0).unwrap();
            let y3 = BigInt::from_str(&test_case.y3.0).unwrap();
            let y4 = BigInt::from_str(&test_case.y4.0).unwrap();
            let y5 = BigInt::from_str(&test_case.y5.0).unwrap();

            let p = CurvePoint::new(x, y);
            let q = CurvePoint::new(x2, y2.clone());
            let mut r = CurvePoint::new(x3, y3);

            let (q_1, q_2) = curve.mul_add(&a, &p, &b, (Some(&q.x), &q.y)).unwrap();
            assert_eq!(q_1, q_2);
            assert_eq!(r, q_1);

            r = CurvePoint::new(x4, y4);
            let r_2 = CurvePoint::new(x5, y5);

            let (r_3, r_4) = curve.mul_add(&a, &p, &b, (None, &y2)).unwrap();
            assert!((r_3 == r && r_4 == r_2) || (r_3 == r_2 && r_4 == r));
        });
    }

    #[test]
    fn mul_add_mdc() {
        let curve = EdwardsCurve::new_mdc().unwrap();
        let test_cases = get_test_vectors::<TestMulAdd>("TestVectorsMulAddMDC.json");
        
        test_mul_add(&curve, &test_cases);
    }

    #[test]
    fn mul_add_curve25519() {
        let curve = EdwardsCurve::new_curve25519().unwrap();
        let test_cases = get_test_vectors::<TestMulAdd>("TestVectorsMulAddCurve25519.json");
        
        test_mul_add(&curve, &test_cases);
    }
}