use std::env;

#[cfg(feature = "simd")]
const SIMD: bool = true;

#[cfg(not(feature = "simd"))]
const SIMD: bool = false;

const FILES: &[&str] = &[
    "argon2/src/argon2.c",
    "argon2/src/core.c",
    "argon2/src/blake2/blake2b.c",
    "argon2/src/encoding.c",
    "argon2/src/thread.c",
    if SIMD {
        "argon2/src/opt.c"
    } else {
        "argon2/src/ref.c"
    },
];

const INCLUDE: &str = "argon2/include";

fn main() {
    let mut builder = cc::Build::new();
    builder
        .files(FILES)
        .include(INCLUDE)
        .flag_if_supported("-pthread")
        .flag_if_supported("-std=c89")
        .warnings(false)
        .extra_warnings(false);

    if SIMD {
        builder.flag_if_supported("-march=native");
    }

    let opt_level = env::var("OPT_LEVEL").unwrap();
    let opt_level = opt_level.parse::<usize>().unwrap();
    if opt_level < 3 {
        builder.flag_if_supported("-g");
    }

    builder.compile("argon2");
}
