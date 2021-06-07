#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

pub const ARGON2_MIN_LANES: u64 = 1;
pub const ARGON2_MAX_LANES: u64 = 0xFFFFFF;

pub const ARGON2_MIN_THREADS: u64 = 1;
pub const ARGON2_MAX_THREADS: u64 = 0xFFFFFF;

pub const ARGON2_SYNC_POINTS: u64 = 4;

pub const ARGON2_MIN_OUTLEN: u64 = 4;
pub const ARGON2_MAX_OUTLEN: u64 = 0xFFFFFF;

pub const ARGON2_MIN_MEMORY: u64 = 2 * ARGON2_SYNC_POINTS;

const ADDRESSING_SPACE: u64 = (std::mem::size_of::<usize>() * 8) as u64;

const fn min(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

const ARGON2_MAX_MEMORY_BITS: u64 = min(32, ADDRESSING_SPACE - 10 - 1);

pub const ARGON2_MAX_MEMORY: u64 = min(0xFFFFFFFF, 1 << ARGON2_MAX_MEMORY_BITS);

pub const ARGON2_MIN_TIME: u64 = 1;
pub const ARGON2_MAX_TIME: u64 = 0xFFFFFFFF;

pub const ARGON2_MIN_PWD_LENGTH: u64 = 0;
pub const ARGON2_MAX_PWD_LENGTH: u64 = 0xFFFFFFFF;

pub const ARGON2_MIN_AD_LENGTH: u64 = 0;
pub const ARGON2_MAX_AD_LENGTH: u64 = 0xFFFFFFFF;

pub const ARGON2_MIN_SALT_LENGTH: u64 = 8;
pub const ARGON2_MAX_SALT_LENGTH: u64 = 0xFFFFFFFF;

pub const ARGON2_MIN_SECRET: u64 = 0;
pub const ARGON2_MAX_SECRET: u64 = 0xFFFFFFFF;

pub const ARGON2_DEFAULT_FLAGS: u32 = 0;
pub const ARGON2_FLAG_CLEAR_PASSWORD: u32 = 1 << 0;
pub const ARGON2_FLAG_CLEAR_SECRET: u32 = 1 << 1;

pub type Argon2_ErrorCodes = libc::c_int;

pub const ARGON2_OK: Argon2_ErrorCodes = 0;
pub const ARGON2_OUTPUT_PTR_NULL: Argon2_ErrorCodes = -1;
pub const ARGON2_OUTPUT_TOO_SHORT: Argon2_ErrorCodes = -2;
pub const ARGON2_OUTPUT_TOO_LONG: Argon2_ErrorCodes = -3;
pub const ARGON2_PWD_TOO_SHORT: Argon2_ErrorCodes = -4;
pub const ARGON2_PWD_TOO_LONG: Argon2_ErrorCodes = -5;
pub const ARGON2_SALT_TOO_SHORT: Argon2_ErrorCodes = -6;
pub const ARGON2_SALT_TOO_LONG: Argon2_ErrorCodes = -7;
pub const ARGON2_AD_TOO_SHORT: Argon2_ErrorCodes = -8;
pub const ARGON2_AD_TOO_LONG: Argon2_ErrorCodes = -9;
pub const ARGON2_SECRET_TOO_SHORT: Argon2_ErrorCodes = -10;
pub const ARGON2_SECRET_TOO_LONG: Argon2_ErrorCodes = -11;
pub const ARGON2_TIME_TOO_SMALL: Argon2_ErrorCodes = -12;
pub const ARGON2_TIME_TOO_LARGE: Argon2_ErrorCodes = -13;
pub const ARGON2_MEMORY_TOO_LITTLE: Argon2_ErrorCodes = -14;
pub const ARGON2_MEMORY_TOO_MUCH: Argon2_ErrorCodes = -15;
pub const ARGON2_LANES_TOO_FEW: Argon2_ErrorCodes = -16;
pub const ARGON2_LANES_TOO_MANY: Argon2_ErrorCodes = -17;
pub const ARGON2_PWD_PTR_MISMATCH: Argon2_ErrorCodes = -18;
pub const ARGON2_SALT_PTR_MISMATCH: Argon2_ErrorCodes = -19;
pub const ARGON2_SECRET_PTR_MISMATCH: Argon2_ErrorCodes = -20;
pub const ARGON2_AD_PTR_MISMATCH: Argon2_ErrorCodes = -21;
pub const ARGON2_MEMORY_ALLOCATION_ERROR: Argon2_ErrorCodes = -22;
pub const ARGON2_FREE_MEMORY_CBK_NULL: Argon2_ErrorCodes = -23;
pub const ARGON2_ALLOCATE_MEMORY_CBK_NULL: Argon2_ErrorCodes = -24;
pub const ARGON2_INCORRECT_PARAMETER: Argon2_ErrorCodes = -25;
pub const ARGON2_INCORRECT_TYPE: Argon2_ErrorCodes = -26;
pub const ARGON2_OUT_PTR_MISMATCH: Argon2_ErrorCodes = -27;
pub const ARGON2_THREADS_TOO_FEW: Argon2_ErrorCodes = -28;
pub const ARGON2_THREADS_TOO_MANY: Argon2_ErrorCodes = -29;
pub const ARGON2_MISSING_ARGS: Argon2_ErrorCodes = -30;
pub const ARGON2_ENCODING_FAIL: Argon2_ErrorCodes = -31;
pub const ARGON2_DECODING_FAIL: Argon2_ErrorCodes = -32;
pub const ARGON2_THREAD_FAIL: Argon2_ErrorCodes = -33;
pub const ARGON2_DECODING_LENGTH_FAIL: Argon2_ErrorCodes = -34;
pub const ARGON2_VERIFY_MISMATCH: Argon2_ErrorCodes = -35;

pub type size_t = libc::c_ulong;

pub type allocate_fptr = ::std::option::Option<
    unsafe extern "C" fn(memory: *mut *mut u8, bytes_to_allocate: size_t) -> libc::c_int,
>;

pub type deallocate_fptr =
    ::std::option::Option<unsafe extern "C" fn(memory: *mut u8, bytes_to_allocate: size_t)>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Argon2_Context {
    pub out: *mut u8,
    pub outlen: u32,
    pub pwd: *mut u8,
    pub pwdlen: u32,
    pub salt: *mut u8,
    pub saltlen: u32,
    pub secret: *mut u8,
    pub secretlen: u32,
    pub ad: *mut u8,
    pub adlen: u32,
    pub t_cost: u32,
    pub m_cost: u32,
    pub lanes: u32,
    pub threads: u32,
    pub version: u32,
    pub allocate_cbk: allocate_fptr,
    pub free_cbk: deallocate_fptr,
    pub flags: u32,
}

pub type argon2_context = Argon2_Context;

pub const Argon2_type_Argon2_d: Argon2_type = 0;
pub const Argon2_type_Argon2_i: Argon2_type = 1;
pub const Argon2_type_Argon2_id: Argon2_type = 2;

pub type Argon2_type = libc::c_uint;
pub use self::Argon2_type as argon2_type;

pub const Argon2_version_ARGON2_VERSION_10: Argon2_version = 0x10;
pub const Argon2_version_ARGON2_VERSION_13: Argon2_version = 0x13;
pub const Argon2_version_ARGON2_VERSION_NUMBER: Argon2_version = Argon2_version_ARGON2_VERSION_13;

pub type Argon2_version = libc::c_uint;
pub use self::Argon2_version as argon2_version;

extern "C" {
    /// Function that gives the string representation of an argon2_type.
    ///
    /// @param type The argon2_type that we want the string for
    ///
    /// @param uppercase Whether the string should have the first letter uppercase
    ///
    /// @return NULL if invalid type, otherwise the string representation.
    pub fn argon2_type2string(ty: argon2_type, uppercase: libc::c_int) -> *const libc::c_char;

    /// Function that performs memory-hard hashing with certain degree of parallelism
    ///
    /// @param  context  Pointer to the Argon2 internal structure
    ///
    /// @return Error code if smth is wrong, ARGON2_OK otherwise
    pub fn argon2_ctx(context: *mut argon2_context, ty: argon2_type) -> libc::c_int;

    /// Hashes a password with Argon2i, producing an encoded hash
    ///
    /// @param t_cost Number of iterations
    ///
    /// @param m_cost Sets memory usage to m_cost kibibytes
    ///
    /// @param parallelism Number of threads and compute lanes
    ///
    /// @param pwd Pointer to password
    ///
    /// @param pwdlen Password size in bytes
    ///
    /// @param salt Pointer to salt
    ///
    /// @param saltlen Salt size in bytes
    ///
    /// @param hashlen Desired length of the hash in bytes
    ///
    /// @param encoded Buffer where to write the encoded hash
    ///
    /// @param encodedlen Size of the buffer (thus max size of the encoded hash)
    ///
    /// @pre   Different parallelism levels will give different results
    ///
    /// @pre   Returns ARGON2_OK if successful
    pub fn argon2i_hash_encoded(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hashlen: libc::size_t,
        encoded: *mut libc::c_char,
        encodedlen: libc::size_t,
    ) -> libc::c_int;

    /// Hashes a password with Argon2i, producing a raw hash at @hash
    ///
    /// @param t_cost Number of iterations
    ///
    /// @param m_cost Sets memory usage to m_cost kibibytes
    ///
    /// @param parallelism Number of threads and compute lanes
    ///
    /// @param pwd Pointer to password
    ///
    /// @param pwdlen Password size in bytes
    ///
    /// @param salt Pointer to salt
    ///
    /// @param saltlen Salt size in bytes
    ///
    /// @param hash Buffer where to write the raw hash - updated by the function
    ///
    /// @param hashlen Desired length of the hash in bytes
    ///
    /// @pre   Different parallelism levels will give different results
    ///
    /// @pre   Returns ARGON2_OK if successful
    pub fn argon2i_hash_raw(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hash: *mut libc::c_void,
        hashlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2d_hash_encoded(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hashlen: libc::size_t,
        encoded: *mut libc::c_char,
        encodedlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2d_hash_raw(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hash: *mut libc::c_void,
        hashlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2id_hash_encoded(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hashlen: libc::size_t,
        encoded: *mut libc::c_char,
        encodedlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2id_hash_raw(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hash: *mut libc::c_void,
        hashlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2_hash(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        salt: *const libc::c_void,
        saltlen: libc::size_t,
        hash: *mut libc::c_void,
        hashlen: libc::size_t,
        encoded: *mut libc::c_char,
        encodedlen: libc::size_t,
        ty: argon2_type,
        version: u32,
    ) -> libc::c_int;

    /// Verifies a password against an encoded string
    ///
    /// Encoded string is restricted as in validate_inputs()
    ///
    /// @param encoded String encoding parameters, salt, hash
    ///
    /// @param pwd Pointer to password
    ///
    /// @pre   Returns ARGON2_OK if successful
    pub fn argon2i_verify(
        encoded: *const libc::c_char,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2d_verify(
        encoded: *const libc::c_char,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2id_verify(
        encoded: *const libc::c_char,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
    ) -> libc::c_int;

    pub fn argon2_verify(
        encoded: *const libc::c_char,
        pwd: *const libc::c_void,
        pwdlen: libc::size_t,
        ty: argon2_type,
    ) -> libc::c_int;

    ///  Argon2d: Version of Argon2 that picks memory blocks depending
    ///  on the password and salt. Only for side-channel-free
    ///  environment!!
    /// ****
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2d_ctx(context: *mut argon2_context) -> libc::c_int;

    /// Argon2i: Version of Argon2 that picks memory blocks
    /// independent on the password and salt. Good for side-channels,
    /// but worse w.r.t. tradeoff attacks if only one pass is used.
    /// ****
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2i_ctx(context: *mut argon2_context) -> libc::c_int;

    /// Argon2id: Version of Argon2 where the first half-pass over memory is
    /// password-independent, the rest are password-dependent (on the password and
    /// salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
    /// better with w.r.t. tradeoff attacks (similar to Argon2d).
    /// ****
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2id_ctx(context: *mut argon2_context) -> libc::c_int;

    /// Verify if a given password is correct for Argon2d hashing
    ///
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @param  hash  The password hash to verify. The length of the hash is
    /// specified by the context outlen member
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2d_verify_ctx(
        context: *mut argon2_context,
        hash: *const libc::c_char,
    ) -> libc::c_int;

    /// Verify if a given password is correct for Argon2i hashing
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @param  hash  The password hash to verify. The length of the hash is
    /// specified by the context outlen member
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2i_verify_ctx(
        context: *mut argon2_context,
        hash: *const libc::c_char,
    ) -> libc::c_int;

    /// Verify if a given password is correct for Argon2id hashing
    ///
    /// @param  context  Pointer to current Argon2 context
    ///
    /// @param  hash  The password hash to verify. The length of the hash is
    /// specified by the context outlen member
    ///
    /// @return  Zero if successful, a non zero error code otherwise
    pub fn argon2id_verify_ctx(
        context: *mut argon2_context,
        hash: *const libc::c_char,
    ) -> libc::c_int;

    pub fn argon2_verify_ctx(
        context: *mut argon2_context,
        hash: *const libc::c_char,
        ty: argon2_type,
    ) -> libc::c_int;

    /// Get the associated error message for given error code
    ///
    /// @return  The error message associated with the given error code
    pub fn argon2_error_message(error_code: libc::c_int) -> *const libc::c_char;

    /// Returns the encoded hash length for the given input parameters
    ///
    /// @param t_cost  Number of iterations
    ///
    /// @param m_cost  Memory usage in kibibytes
    ///
    /// @param parallelism  Number of threads; used to compute lanes
    ///
    /// @param saltlen  Salt size in bytes
    ///
    /// @param hashlen  Hash size in bytes
    ///
    /// @param type The argon2_type that we want the encoded length for
    ///
    /// @return  The encoded hash length in bytes
    pub fn argon2_encodedlen(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        saltlen: u32,
        hashlen: u32,
        ty: argon2_type,
    ) -> size_t;
}
