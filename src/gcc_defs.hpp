#ifndef GCC_DEFS_HPP
#define GCC_DEFS_HPP

#if __GNUC__ >= 3
# define GCC_INLINE       inline __attribute__ ((always_inline))
# define GCC_NOINLINE     __attribute__ ((noinline))
# define GCC_PURE         __attribute__ ((pure))
# define GCC_CONST        __attribute__ ((const))
# define GCC_NORETURN     __attribute__ ((noreturn))
# define GCC_MALLOC       __attribute__ ((malloc))
# define GCC_MUST_CHECK   __attribute__ ((warn_unused_result))
# define GCC_DEPRECATED   __attribute__ ((deprecated))
# define GCC_USED         __attribute__ ((used))
# define GCC_UNUSED       __attribute__ ((unused))
# define GCC_PACKED       __attribute__ ((packed))
# define GCC_ALIGN(x)     __attribute__ ((aligned (x)))
# define GCC_ALIGN_MAX    __attribute__ ((aligned))
# define GCC_PRINTF(x, y) __attribute__ ((format(printf, x, y)))
# define GCC_STV_HIDDEN   __attribute__ ((visibility ("hidden")))
# define GCC_STV_DEFAULT  __attribute__ ((visibility ("default")))
# define likely(x)        __builtin_expect (!!(x), 1)
# define unlikely(x)      __builtin_expect (!!(x), 0)
#else
# define GCC_NOINLINE     /* no noinline */
# define GCC_PURE         /* no pure */
# define GCC_CONST        /* no const */
# define GCC_NORETURN     /* no noreturn */
# define GCC_MALLOC       /* no malloc */
# define GCC_MUST_CHECK   /* no warn_unused_result */
# define GCC_DEPRECATED   /* no deprecated */
# define GCC_USED         /* no used */
# define GCC_UNUSED       /* no unused */
# define GCC_PACKED       /* no packed */
# define GCC_ALIGN(x)     /* no aligned */
# define GCC_ALIGN_MAX    /* no align_max */
# define GCC_PRINTF(x, y) /* no format printf */
# define GCC_STV_HIDDEN   /* no hidden visibility */
# define GCC_STV_DEFAULT  /* no default visibility */
# define likely(x)        (x)
# define unlikely(x)      (x)
#endif

#endif // GCC_DEFS_HPP
