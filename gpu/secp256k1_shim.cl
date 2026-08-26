/*
 * Compatibility shim so hashcat's vendored inc_ecc_secp256k1.{h,cl} compile
 * standalone (outside hashcat's own build, which normally defines these).
 */
#define IS_OPENCL 1

typedef uint  u32;
typedef ulong u64;

#define DECLSPEC static inline
#define PRIVATE_AS
#define GLOBAL_AS   __global
#define CONSTANT_AS __constant
#define LOCAL_AS    __local

#define SECP256K1_TMPS_TYPE PRIVATE_AS
