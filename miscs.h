#ifndef MISCS_DSCAO__
#define MISCS_DSCAO__

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely(x)	__builtin_expect(!!(x), 1)

#define READ_ONCE(x)	(*(const volatile typeof(x) *)&(x))

#define WRITE_ONCE(x, val)			\
do {						\
	*((volatile typeof(x) *)&(x)) = (val);	\
} while (0)

#endif /* MISCS_DSCAO__ */
