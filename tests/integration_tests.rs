use argon2_sys::{
    argon2_error_message, argon2_hash, argon2_verify, Argon2_ErrorCodes_ARGON2_DECODING_FAIL,
    Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE, Argon2_ErrorCodes_ARGON2_OK,
    Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH, Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT,
    Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH, Argon2_type_Argon2_i, Argon2_type_Argon2_id,
    Argon2_version_ARGON2_VERSION_10, Argon2_version_ARGON2_VERSION_13,
};
use std::ffi::{CStr, CString};

struct Output {
    code: i32,
    hash: Vec<u8>,
    encoded: Vec<u8>,
}

fn run_hash(t: u32, m: u32, p: u32, password: &str, salt: &str, ty: u32, version: u32) -> Output {
    let mut hash_buffer = vec![0u8; 32];
    let mut encoded_buffer = vec![0u8; 108];
    let (hash, hashlen) = (
        hash_buffer.as_mut_ptr() as *mut libc::c_void,
        hash_buffer.len(),
    );
    let (encoded, encodedlen) = (encoded_buffer.as_mut_ptr() as *mut i8, encoded_buffer.len());
    let (pwd, pwdlen) = (
        password.as_bytes().as_ptr() as *const libc::c_void,
        password.len(),
    );
    let (salt, saltlen) = (salt.as_bytes().as_ptr() as *const libc::c_void, salt.len());
    let code = unsafe {
        argon2_hash(
            t,
            1 << m,
            p,
            pwd,
            pwdlen,
            salt,
            saltlen,
            hash,
            hashlen,
            encoded,
            encodedlen,
            ty,
            version,
        )
    };
    Output {
        code,
        hash: hash_buffer,
        encoded: encoded_buffer,
    }
}

fn run_verify(encoded: &str, password: &str, ty: u32) -> i32 {
    let encoded_c = CString::new(encoded).unwrap();
    let password_c = CString::new(password).unwrap();
    unsafe {
        argon2_verify(
            encoded_c.as_ptr(),
            password_c.as_ptr() as *const libc::c_void,
            password.len(),
            ty,
        )
    }
}

mod argon2i_v10 {
    use super::*;

    const TY: u32 = Argon2_type_Argon2_i;
    const VERSION: u32 = Argon2_version_ARGON2_VERSION_10;

    #[test]
    fn case_1() {
        let output = run_hash(2, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694")
                .unwrap(),
        );
    }

    #[test]
    fn case_2() {
        let output = run_hash(2, 18, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467")
                .unwrap(),
        );
    }

    #[test]
    fn case_3() {
        let output = run_hash(2, 8, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06")
                .unwrap(),
        );
    }

    #[test]
    fn case_4() {
        let output = run_hash(2, 8, 2, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb")
                .unwrap(),
        );
    }

    #[test]
    fn case_5() {
        let output = run_hash(1, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2")
                .unwrap(),
        );
    }

    #[test]
    fn case_6() {
        let output = run_hash(4, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b")
                .unwrap(),
        );
    }

    #[test]
    fn case_7() {
        let output = run_hash(2, 16, 1, "differentpassword", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3")
                .unwrap(),
        );
    }

    #[test]
    fn case_8() {
        let output = run_hash(2, 16, 1, "password", "diffsalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        assert_eq!(
            output.hash,
            hex::decode("79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497")
                .unwrap(),
        );
    }

    // Error state tests

    // Handle an invalid encoding correctly (it is missing a $)
    #[test]
    fn case_9() {
        let password = "password";
        let encoded =
            "$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_DECODING_FAIL);
    }

    // Handle an invalid encoding correctly (it is missing a $)
    #[test]
    fn case_10() {
        let password = "password";
        let encoded =
            "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_DECODING_FAIL);
    }

    // Handle an invalid encoding correctly (salt is too short)
    #[test]
    fn case_11() {
        let password = "password";
        let encoded = "$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT);
    }

    // Handle an mismatching hash (the encoded password is "passwore")
    #[test]
    fn case_12() {
        let password = "password";
        let encoded =
            "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH);
    }

    #[test]
    fn case_13() {
        let msg_ptr = unsafe { argon2_error_message(Argon2_ErrorCodes_ARGON2_DECODING_FAIL) };
        let msg = unsafe { CStr::from_ptr(msg_ptr) };
        assert_eq!(msg.to_str().unwrap(), "Decoding failed");
    }
}

mod argon2i_v13 {
    use super::*;

    const TY: u32 = Argon2_type_Argon2_i;
    const VERSION: u32 = Argon2_version_ARGON2_VERSION_13;

    #[test]
    fn case_14() {
        let output = run_hash(2, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_15() {
        let output = run_hash(2, 18, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_16() {
        let output = run_hash(2, 8, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_17() {
        let output = run_hash(2, 8, 2, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_18() {
        let output = run_hash(1, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_19() {
        let output = run_hash(4, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_20() {
        let output = run_hash(2, 16, 1, "differentpassword", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_21() {
        let output = run_hash(2, 16, 1, "password", "diffsalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    // Error state tests

    // Handle an invalid encoding correctly (it is missing a $)
    #[test]
    fn case_22() {
        let password = "password";
        let encoded =
            "$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_DECODING_FAIL);
    }

    // Handle an invalid encoding correctly (it is missing a $)
    #[test]
    fn case_23() {
        let password = "password";
        let encoded =
            "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_DECODING_FAIL);
    }

    // Handle an invalid encoding correctly (salt is too short)
    #[test]
    fn case_24() {
        let password = "password";
        let encoded = "$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT);
    }

    // Handle an invalid encoding correctly (the encoded password is "passwore")
    #[test]
    fn case_25() {
        let password = "password";
        let encoded =
            "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM";
        let ret = run_verify(encoded, password, TY);
        assert_eq!(ret, Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH);
    }
}

mod argon2id_v13 {
    use super::*;

    const TY: u32 = Argon2_type_Argon2_id;
    const VERSION: u32 = Argon2_version_ARGON2_VERSION_13;

    #[test]
    fn case_26() {
        let output = run_hash(2, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_27() {
        let output = run_hash(2, 18, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_28() {
        let output = run_hash(2, 8, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_29() {
        let output = run_hash(2, 8, 2, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_30() {
        let output = run_hash(1, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_31() {
        let output = run_hash(4, 16, 1, "password", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_32() {
        let output = run_hash(2, 16, 1, "differentpassword", "somesalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    #[test]
    fn case_33() {
        let output = run_hash(2, 16, 1, "password", "diffsalt", TY, VERSION);
        assert_eq!(output.code, Argon2_ErrorCodes_ARGON2_OK);
        let hash = hex::decode("bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c")
            .unwrap();
        assert_eq!(output.hash, hash);
        let encoded =
            b"$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw";
        assert_eq!(&output.encoded[..encoded.len()], encoded);
    }

    // Common error state tests

    #[test]
    fn case_34() {
        let password = "password";
        let salt = "diffsalt";

        let mut hash_buffer = vec![0u8; 32];
        let (hash, hashlen) = (
            hash_buffer.as_mut_ptr() as *mut libc::c_void,
            hash_buffer.len(),
        );
        let (pwd, pwdlen) = (
            password.as_bytes().as_ptr() as *const libc::c_void,
            password.len(),
        );
        let (salt, saltlen) = (salt.as_bytes().as_ptr() as *const libc::c_void, salt.len());
        let code = unsafe {
            argon2_hash(
                2,
                1,
                1,
                pwd,
                pwdlen,
                salt,
                saltlen,
                hash,
                hashlen,
                std::ptr::null_mut(),
                0,
                TY,
                VERSION,
            )
        };

        assert_eq!(code, Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE);
    }

    #[test]
    fn case_35() {
        let password = "password";
        let salt = "diffsalt";

        let mut hash_buffer = vec![0u8; 32];
        let (hash, hashlen) = (
            hash_buffer.as_mut_ptr() as *mut libc::c_void,
            hash_buffer.len(),
        );
        let (_, pwdlen) = (
            password.as_bytes().as_ptr() as *const libc::c_void,
            password.len(),
        );
        let (salt, saltlen) = (salt.as_bytes().as_ptr() as *const libc::c_void, salt.len());
        let code = unsafe {
            argon2_hash(
                2,
                1 << 12,
                1,
                std::ptr::null(),
                pwdlen,
                salt,
                saltlen,
                hash,
                hashlen,
                std::ptr::null_mut(),
                0,
                TY,
                VERSION,
            )
        };

        assert_eq!(code, Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH);
    }

    #[test]
    fn case_36() {
        let password = "password";
        let salt = "s";

        let mut hash_buffer = vec![0u8; 32];
        let (hash, hashlen) = (
            hash_buffer.as_mut_ptr() as *mut libc::c_void,
            hash_buffer.len(),
        );
        let (pwd, pwdlen) = (
            password.as_bytes().as_ptr() as *const libc::c_void,
            password.len(),
        );
        let (salt, saltlen) = (salt.as_bytes().as_ptr() as *const libc::c_void, salt.len());
        let code = unsafe {
            argon2_hash(
                2,
                1 << 12,
                1,
                pwd,
                pwdlen,
                salt,
                saltlen,
                hash,
                hashlen,
                std::ptr::null_mut(),
                0,
                TY,
                VERSION,
            )
        };

        assert_eq!(code, Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT);
    }
}
