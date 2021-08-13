#ifdef WITH_OPENSSL

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "openbsd-compat/openssl-compat.h"

#include "sshbuf.h"


#ifndef HAVE_EVP_SHA256
# define EVP_sha256 NULL
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 NULL
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 NULL
#endif

struct ssh_digest_ctx {
	int alg;
	void *mdctx;
};

struct ssh_hmac_ctx {
	int			 alg;
	struct ssh_digest_ctx	*ictx;
	struct ssh_digest_ctx	*octx;
	struct ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};