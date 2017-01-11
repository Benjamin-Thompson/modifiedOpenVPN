/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#include <openssl/e_os2.h>
#if !defined(OPENSSL_SYS_MSDOS) || defined(__DJGPP__) || defined(__MINGW32__)
# include <sys/types.h>
# include <unistd.h>
#else
# include <process.h>
typedef int pid_t;
#endif

#if defined(OPENSSL_SYS_NETWARE) && defined(NETWARE_CLIB)
# define getpid GetThreadID
extern int GetThreadID(void);
#elif defined(_WIN32) && !defined(__WATCOMC__)
# define getpid _getpid
#endif

#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/buffer.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif

#ifndef OPENSSL_NO_HW
# ifndef OPENSSL_NO_HW_AEP
#  ifdef FLAT_INC
#   include "tunnel.h"
#  else
#   include "vendor_defns/tunnel.h"
#  endif

#  define TUNNEL_LIB_NAME "tunnel engine"
#  define FAIL_TO_SW 0x10101010

#  include "e_tunnel_err.c"

static int tunnel_init(ENGINE *e);
static int tunnel_finish(ENGINE *e);
static int tunnel_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
static int tunnel_destroy(ENGINE *e);

static TUNNEL_RV tunnel_get_connection(TUNNEL_CONNECTION_HNDL_PTR hConnection);
static TUNNEL_RV tunnel_return_connection(TUNNEL_CONNECTION_HNDL hConnection);
static TUNNEL_RV tunnel_close_connection(TUNNEL_CONNECTION_HNDL hConnection);
static TUNNEL_RV tunnel_close_all_connections(int use_engine_lock, int *in_use);

/* BIGNUM stuff */
#  ifndef OPENSSL_NO_RSA
static int tunnel_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx);

static TUNNEL_RV tunnel_mod_exp_crt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *q, const BIGNUM *dmp1,
                              const BIGNUM *dmq1, const BIGNUM *iqmp,
                              BN_CTX *ctx);
#  endif

/* RSA stuff */
#  ifndef OPENSSL_NO_RSA
static int tunnel_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                           BN_CTX *ctx);
#  endif

/* This function is aliased to mod_exp (with the mont stuff dropped). */
#  ifndef OPENSSL_NO_RSA
static int tunnel_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
#  endif

/* DSA stuff */
#  ifndef OPENSSL_NO_DSA
static int tunnel_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                           BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
                           BN_CTX *ctx, BN_MONT_CTX *in_mont);

static int tunnel_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
                           const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                           BN_MONT_CTX *m_ctx);
#  endif

/* DH stuff */
/* This function is aliased to mod_exp (with the DH and mont dropped). */
#  ifndef OPENSSL_NO_DH
static int tunnel_mod_exp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                          BN_MONT_CTX *m_ctx);
#  endif

/* rand stuff   */
#  ifdef TUNNELRAND
static int tunnel_rand(unsigned char *buf, int num);
static int tunnel_rand_status(void);
#  endif

/* Bignum conversion stuff */
static TUNNEL_RV GetBigNumSize(TUNNEL_VOID_PTR ArbBigNum, TUNNEL_U32 *BigNumSize);
static TUNNEL_RV MakeTUNNELBigNum(TUNNEL_VOID_PTR ArbBigNum, TUNNEL_U32 BigNumSize,
                            unsigned char *TUNNEL_BigNum);
static TUNNEL_RV ConvertTUNNELBigNum(void *ArbBigNum, TUNNEL_U32 BigNumSize,
                               unsigned char *TUNNEL_BigNum);

/* The definitions for control commands specific to this engine */
#  define TUNNEL_CMD_SO_PATH         ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN tunnel_cmd_defns[] = {
    {TUNNEL_CMD_SO_PATH,
     "SO_PATH",
     "Specifies the path to the 'tunnel' shared library",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

#  ifndef OPENSSL_NO_RSA
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD tunnel_rsa = {
    "Aep RSA method",
    NULL,                       /* rsa_pub_encrypt */
    NULL,                       /* rsa_pub_decrypt */
    NULL,                       /* rsa_priv_encrypt */
    NULL,                       /* rsa_priv_encrypt */
    tunnel_rsa_mod_exp,            /* rsa_mod_exp */
    tunnel_mod_exp_mont,           /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* rsa_sign */
    NULL,                       /* rsa_verify */
    NULL                        /* rsa_keygen */
};
#  endif

#  ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD tunnel_dsa = {
    "Aep DSA method",
    NULL,                       /* dsa_do_sign */
    NULL,                       /* dsa_sign_setup */
    NULL,                       /* dsa_do_verify */
    tunnel_dsa_mod_exp,            /* dsa_mod_exp */
    tunnel_mod_exp_dsa,            /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* dsa_paramgen */
    NULL                        /* dsa_keygen */
};
#  endif

#  ifndef OPENSSL_NO_DH
/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD tunnel_dh = {
    "Aep DH method",
    NULL,
    NULL,
    tunnel_mod_exp_dh,
    NULL,
    NULL,
    0,
    NULL,
    NULL
};
#  endif

#  ifdef TUNNELRAND
/* our internal RAND_method that we provide pointers to  */
static RAND_METHOD tunnel_random = {
    /*
     * "TUNNEL RAND method",
     */
    NULL,
    tunnel_rand,
    NULL,
    NULL,
    tunnel_rand,
    tunnel_rand_status,
};
#  endif

/*
 * Define an array of structures to hold connections
 */
static TUNNEL_CONNECTION_ENTRY tunnel_app_conn_table[MAX_PROCESS_CONNECTIONS];

/*
 * Used to determine if this is a new process
 */
static pid_t recorded_pid = 0;

#  ifdef TUNNELRAND
static TUNNEL_U8 rand_block[RAND_BLK_SIZE];
static TUNNEL_U32 rand_block_bytes = 0;
#  endif

/* Constants used when creating the ENGINE */
static const char *engine_tunnel_id = "tunnel";
static const char *engine_tunnel_name = "Aep hardware engine support";

static int max_key_len = 2176;

/*
 * This internal function is used by ENGINE_tunnel() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_tunnel(ENGINE *e)
{
#  ifndef OPENSSL_NO_RSA
    const RSA_METHOD *meth1;
#  endif
#  ifndef OPENSSL_NO_DSA
    const DSA_METHOD *meth2;
#  endif
#  ifndef OPENSSL_NO_DH
    const DH_METHOD *meth3;
#  endif

    if (!ENGINE_set_id(e, engine_tunnel_id) ||
        !ENGINE_set_name(e, engine_tunnel_name) ||
#  ifndef OPENSSL_NO_RSA
        !ENGINE_set_RSA(e, &tunnel_rsa) ||
#  endif
#  ifndef OPENSSL_NO_DSA
        !ENGINE_set_DSA(e, &tunnel_dsa) ||
#  endif
#  ifndef OPENSSL_NO_DH
        !ENGINE_set_DH(e, &tunnel_dh) ||
#  endif
#  ifdef TUNNELRAND
        !ENGINE_set_RAND(e, &tunnel_random) ||
#  endif
        !ENGINE_set_init_function(e, tunnel_init) ||
        !ENGINE_set_destroy_function(e, tunnel_destroy) ||
        !ENGINE_set_finish_function(e, tunnel_finish) ||
        !ENGINE_set_ctrl_function(e, tunnel_ctrl) ||
        !ENGINE_set_cmd_defns(e, tunnel_cmd_defns))
        return 0;

#  ifndef OPENSSL_NO_RSA
    /*
     * We know that the "PKCS1_SSLeay()" functions hook properly to the
     * tunnel-specific mod_exp and mod_exp_crt so we use those functions. NB: We
     * don't use ENGINE_openssl() or anything "more generic" because
     * something like the RSAref code may not hook properly, and if you own
     * one of these cards then you have the right to do RSA operations on it
     * anyway!
     */
    meth1 = RSA_PKCS1_SSLeay();
    tunnel_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
    tunnel_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
    tunnel_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
    tunnel_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
#  endif

#  ifndef OPENSSL_NO_DSA
    /*
     * Use the DSA_OpenSSL() method and just hook the mod_exp-ish bits.
     */
    meth2 = DSA_OpenSSL();
    tunnel_dsa.dsa_do_sign = meth2->dsa_do_sign;
    tunnel_dsa.dsa_sign_setup = meth2->dsa_sign_setup;
    tunnel_dsa.dsa_do_verify = meth2->dsa_do_verify;

    tunnel_dsa = *DSA_get_default_method();
    tunnel_dsa.dsa_mod_exp = tunnel_dsa_mod_exp;
    tunnel_dsa.bn_mod_exp = tunnel_mod_exp_dsa;
#  endif

#  ifndef OPENSSL_NO_DH
    /* Much the same for Diffie-Hellman */
    meth3 = DH_OpenSSL();
    tunnel_dh.generate_key = meth3->generate_key;
    tunnel_dh.compute_key = meth3->compute_key;
    tunnel_dh.bn_mod_exp = meth3->bn_mod_exp;
#  endif

    /* Ensure the tunnel error handling is set up */
    ERR_load_TUNNELHK_strings();

    return 1;
}

#  ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_tunnel_id) != 0))
        return 0;
    if (!bind_tunnel(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#  else
static ENGINE *engine_tunnel(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_tunnel(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_tunnel(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_tunnel();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#  endif

/*
 * This is a process-global DSO handle used for loading and unloading the Aep
 * library. NB: This is only set (or unset) during an init() or finish() call
 * (reference counts permitting) and they're operating with global locks, so
 * this should be thread-safe implicitly.
 */
static DSO *tunnel_dso = NULL;

/*
 * These are the static string constants for the DSO file name and the
 * function symbol names to bind to.
 */
static const char *TUNNEL_LIBNAME = NULL;
static const char *get_TUNNEL_LIBNAME(void)
{
    if (TUNNEL_LIBNAME)
        return TUNNEL_LIBNAME;
    return "tunnel";
}

static void free_TUNNEL_LIBNAME(void)
{
    if (TUNNEL_LIBNAME)
        OPENSSL_free((void *)TUNNEL_LIBNAME);
    TUNNEL_LIBNAME = NULL;
}

static long set_TUNNEL_LIBNAME(const char *name)
{
    free_TUNNEL_LIBNAME();
    return ((TUNNEL_LIBNAME = BUF_strdup(name)) != NULL ? 1 : 0);
}

static const char *TUNNEL_F1 = "TUNNEL_ModExp";
static const char *TUNNEL_F2 = "TUNNEL_ModExpCrt";
#  ifdef TUNNELRAND
static const char *TUNNEL_F3 = "TUNNEL_GenRandom";
#  endif
static const char *TUNNEL_F4 = "TUNNEL_Finalize";
static const char *TUNNEL_F5 = "TUNNEL_Initialize";
static const char *TUNNEL_F6 = "TUNNEL_OpenConnection";
static const char *TUNNEL_F7 = "TUNNEL_SetBNCallBacks";
static const char *TUNNEL_F8 = "TUNNEL_CloseConnection";

/*
 * These are the function pointers that are (un)set when the library has
 * successfully (un)loaded.
 */
static t_TUNNEL_OpenConnection *p_TUNNEL_OpenConnection = NULL;
static t_TUNNEL_CloseConnection *p_TUNNEL_CloseConnection = NULL;
static t_TUNNEL_ModExp *p_TUNNEL_ModExp = NULL;
static t_TUNNEL_ModExpCrt *p_TUNNEL_ModExpCrt = NULL;
#  ifdef TUNNELRAND
static t_TUNNEL_GenRandom *p_TUNNEL_GenRandom = NULL;
#  endif
static t_TUNNEL_Initialize *p_TUNNEL_Initialize = NULL;
static t_TUNNEL_Finalize *p_TUNNEL_Finalize = NULL;
static t_TUNNEL_SetBNCallBacks *p_TUNNEL_SetBNCallBacks = NULL;

/* (de)initialisation functions. */
static int tunnel_init(ENGINE *e)
{
    t_TUNNEL_ModExp *p1;
    t_TUNNEL_ModExpCrt *p2;
#  ifdef TUNNELRAND
    t_TUNNEL_GenRandom *p3;
#  endif
    t_TUNNEL_Finalize *p4;
    t_TUNNEL_Initialize *p5;
    t_TUNNEL_OpenConnection *p6;
    t_TUNNEL_SetBNCallBacks *p7;
    t_TUNNEL_CloseConnection *p8;

    int to_return = 0;

    if (tunnel_dso != NULL) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_INIT, TUNNELHK_R_ALREADY_LOADED);
        goto err;
    }
    /* Attempt to load libtunnel.so. */

    tunnel_dso = DSO_load(NULL, get_TUNNEL_LIBNAME(), NULL, 0);

    if (tunnel_dso == NULL) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_INIT, TUNNELHK_R_NOT_LOADED);
        goto err;
    }

    if (!(p1 = (t_TUNNEL_ModExp *) DSO_bind_func(tunnel_dso, TUNNEL_F1)) ||
        !(p2 = (t_TUNNEL_ModExpCrt *) DSO_bind_func(tunnel_dso, TUNNEL_F2)) ||
#  ifdef TUNNELRAND
        !(p3 = (t_TUNNEL_GenRandom *) DSO_bind_func(tunnel_dso, TUNNEL_F3)) ||
#  endif
        !(p4 = (t_TUNNEL_Finalize *) DSO_bind_func(tunnel_dso, TUNNEL_F4)) ||
        !(p5 = (t_TUNNEL_Initialize *) DSO_bind_func(tunnel_dso, TUNNEL_F5)) ||
        !(p6 = (t_TUNNEL_OpenConnection *) DSO_bind_func(tunnel_dso, TUNNEL_F6)) ||
        !(p7 = (t_TUNNEL_SetBNCallBacks *) DSO_bind_func(tunnel_dso, TUNNEL_F7)) ||
        !(p8 = (t_TUNNEL_CloseConnection *) DSO_bind_func(tunnel_dso, TUNNEL_F8))) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_INIT, TUNNELHK_R_NOT_LOADED);
        goto err;
    }

    /* Copy the pointers */

    p_TUNNEL_ModExp = p1;
    p_TUNNEL_ModExpCrt = p2;
#  ifdef TUNNELRAND
    p_TUNNEL_GenRandom = p3;
#  endif
    p_TUNNEL_Finalize = p4;
    p_TUNNEL_Initialize = p5;
    p_TUNNEL_OpenConnection = p6;
    p_TUNNEL_SetBNCallBacks = p7;
    p_TUNNEL_CloseConnection = p8;

    to_return = 1;

    return to_return;

 err:

    if (tunnel_dso)
        DSO_free(tunnel_dso);
    tunnel_dso = NULL;

    p_TUNNEL_OpenConnection = NULL;
    p_TUNNEL_ModExp = NULL;
    p_TUNNEL_ModExpCrt = NULL;
#  ifdef TUNNELRAND
    p_TUNNEL_GenRandom = NULL;
#  endif
    p_TUNNEL_Initialize = NULL;
    p_TUNNEL_Finalize = NULL;
    p_TUNNEL_SetBNCallBacks = NULL;
    p_TUNNEL_CloseConnection = NULL;

    return to_return;
}

/* Destructor (complements the "ENGINE_tunnel()" constructor) */
static int tunnel_destroy(ENGINE *e)
{
    free_TUNNEL_LIBNAME();
    ERR_unload_TUNNELHK_strings();
    return 1;
}

static int tunnel_finish(ENGINE *e)
{
    int to_return = 0, in_use;
    TUNNEL_RV rv;

    if (tunnel_dso == NULL) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_FINISH, TUNNELHK_R_NOT_LOADED);
        goto err;
    }

    rv = tunnel_close_all_connections(0, &in_use);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_FINISH, TUNNELHK_R_CLOSE_HANDLES_FAILED);
        goto err;
    }
    if (in_use) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_FINISH, TUNNELHK_R_CONNECTIONS_IN_USE);
        goto err;
    }

    rv = p_TUNNEL_Finalize();
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_FINISH, TUNNELHK_R_FINALIZE_FAILED);
        goto err;
    }

    if (!DSO_free(tunnel_dso)) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_FINISH, TUNNELHK_R_UNIT_FAILURE);
        goto err;
    }

    tunnel_dso = NULL;
    p_TUNNEL_CloseConnection = NULL;
    p_TUNNEL_OpenConnection = NULL;
    p_TUNNEL_ModExp = NULL;
    p_TUNNEL_ModExpCrt = NULL;
#  ifdef TUNNELRAND
    p_TUNNEL_GenRandom = NULL;
#  endif
    p_TUNNEL_Initialize = NULL;
    p_TUNNEL_Finalize = NULL;
    p_TUNNEL_SetBNCallBacks = NULL;

    to_return = 1;
 err:
    return to_return;
}

static int tunnel_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int initialised = ((tunnel_dso == NULL) ? 0 : 1);
    switch (cmd) {
    case TUNNEL_CMD_SO_PATH:
        if (p == NULL) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_CTRL, ERR_R_PASSED_NULL_PARAMETER);
            return 0;
        }
        if (initialised) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_CTRL, TUNNELHK_R_ALREADY_LOADED);
            return 0;
        }
        return set_TUNNEL_LIBNAME((const char *)p);
    default:
        break;
    }
    TUNNELHKerr(TUNNELHK_F_TUNNEL_CTRL, TUNNELHK_R_CTRL_COMMAND_NOT_IMPLEMENTED);
    return 0;
}

static int tunnel_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx)
{
    int to_return = 0;
    int r_len = 0;
    TUNNEL_CONNECTION_HNDL hConnection;
    TUNNEL_RV rv;

    r_len = BN_num_bits(m);

    /* Perform in software if modulus is too large for hardware. */

    if (r_len > max_key_len) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP, TUNNELHK_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
        return BN_mod_exp(r, a, p, m, ctx);
    }

    /*
     * Grab a connection from the pool
     */
    rv = tunnel_get_connection(&hConnection);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP, TUNNELHK_R_GET_HANDLE_FAILED);
        return BN_mod_exp(r, a, p, m, ctx);
    }

    /*
     * To the card with the mod exp
     */
    rv = p_TUNNEL_ModExp(hConnection, (void *)a, (void *)p, (void *)m, (void *)r,
                      NULL);

    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP, TUNNELHK_R_MOD_EXP_FAILED);
        rv = tunnel_close_connection(hConnection);
        return BN_mod_exp(r, a, p, m, ctx);
    }

    /*
     * Return the connection to the pool
     */
    rv = tunnel_return_connection(hConnection);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP, TUNNELHK_R_RETURN_CONNECTION_FAILED);
        goto err;
    }

    to_return = 1;
 err:
    return to_return;
}

#  ifndef OPENSSL_NO_RSA
static TUNNEL_RV tunnel_mod_exp_crt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *q, const BIGNUM *dmp1,
                              const BIGNUM *dmq1, const BIGNUM *iqmp,
                              BN_CTX *ctx)
{
    TUNNEL_RV rv = TUNNEL_R_OK;
    TUNNEL_CONNECTION_HNDL hConnection;

    /*
     * Grab a connection from the pool
     */
    rv = tunnel_get_connection(&hConnection);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP_CRT, TUNNELHK_R_GET_HANDLE_FAILED);
        return FAIL_TO_SW;
    }

    /*
     * To the card with the mod exp
     */
    rv = p_TUNNEL_ModExpCrt(hConnection, (void *)a, (void *)p, (void *)q,
                         (void *)dmp1, (void *)dmq1, (void *)iqmp, (void *)r,
                         NULL);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP_CRT, TUNNELHK_R_MOD_EXP_CRT_FAILED);
        rv = tunnel_close_connection(hConnection);
        return FAIL_TO_SW;
    }

    /*
     * Return the connection to the pool
     */
    rv = tunnel_return_connection(hConnection);
    if (rv != TUNNEL_R_OK) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_MOD_EXP_CRT, TUNNELHK_R_RETURN_CONNECTION_FAILED);
        goto err;
    }

 err:
    return rv;
}
#  endif

#  ifdef TUNNELRAND
static int tunnel_rand(unsigned char *buf, int len)
{
    TUNNEL_RV rv = TUNNEL_R_OK;
    TUNNEL_CONNECTION_HNDL hConnection;

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    /*
     * Can the request be serviced with what's already in the buffer?
     */
    if (len <= rand_block_bytes) {
        memcpy(buf, &rand_block[RAND_BLK_SIZE - rand_block_bytes], len);
        rand_block_bytes -= len;
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    } else
        /*
         * If not the get another block of random bytes
         */
    {
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

        rv = tunnel_get_connection(&hConnection);
        if (rv != TUNNEL_R_OK) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_RAND, TUNNELHK_R_GET_HANDLE_FAILED);
            goto err_nounlock;
        }

        if (len > RAND_BLK_SIZE) {
            rv = p_TUNNEL_GenRandom(hConnection, len, 2, buf, NULL);
            if (rv != TUNNEL_R_OK) {
                TUNNELHKerr(TUNNELHK_F_TUNNEL_RAND, TUNNELHK_R_GET_RANDOM_FAILED);
                goto err_nounlock;
            }
        } else {
            CRYPTO_w_lock(CRYPTO_LOCK_RAND);

            rv = p_TUNNEL_GenRandom(hConnection, RAND_BLK_SIZE, 2,
                                 &rand_block[0], NULL);
            if (rv != TUNNEL_R_OK) {
                TUNNELHKerr(TUNNELHK_F_TUNNEL_RAND, TUNNELHK_R_GET_RANDOM_FAILED);

                goto err;
            }

            rand_block_bytes = RAND_BLK_SIZE;

            memcpy(buf, &rand_block[RAND_BLK_SIZE - rand_block_bytes], len);
            rand_block_bytes -= len;

            CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
        }

        rv = tunnel_return_connection(hConnection);
        if (rv != TUNNEL_R_OK) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_RAND, TUNNELHK_R_RETURN_CONNECTION_FAILED);

            goto err_nounlock;
        }
    }

    return 1;
 err:
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
 err_nounlock:
    return 0;
}

static int tunnel_rand_status(void)
{
    return 1;
}
#  endif

#  ifndef OPENSSL_NO_RSA
static int tunnel_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    int to_return = 0;
    TUNNEL_RV rv = TUNNEL_R_OK;

    if (!tunnel_dso) {
        TUNNELHKerr(TUNNELHK_F_TUNNEL_RSA_MOD_EXP, TUNNELHK_R_NOT_LOADED);
        goto err;
    }

    /*
     * See if we have all the necessary bits for a crt
     */
    if (rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
        rv = tunnel_mod_exp_crt(r0, I, rsa->p, rsa->q, rsa->dmp1, rsa->dmq1,
                             rsa->iqmp, ctx);

        if (rv == FAIL_TO_SW) {
            const RSA_METHOD *meth = RSA_PKCS1_SSLeay();
            to_return = (*meth->rsa_mod_exp) (r0, I, rsa, ctx);
            goto err;
        } else if (rv != TUNNEL_R_OK)
            goto err;
    } else {
        if (!rsa->d || !rsa->n) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_RSA_MOD_EXP, TUNNELHK_R_MISSING_KEY_COMPONENTS);
            goto err;
        }

        rv = tunnel_mod_exp(r0, I, rsa->d, rsa->n, ctx);
        if (rv != TUNNEL_R_OK)
            goto err;

    }

    to_return = 1;

 err:
    return to_return;
}
#  endif

#  ifndef OPENSSL_NO_DSA
static int tunnel_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                           BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
                           BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    BIGNUM t;
    int to_return = 0;
    BN_init(&t);

    /* let rr = a1 ^ p1 mod m */
    if (!tunnel_mod_exp(rr, a1, p1, m, ctx))
        goto end;
    /* let t = a2 ^ p2 mod m */
    if (!tunnel_mod_exp(&t, a2, p2, m, ctx))
        goto end;
    /* let rr = rr * t mod m */
    if (!BN_mod_mul(rr, rr, &t, m, ctx))
        goto end;
    to_return = 1;
 end:
    BN_free(&t);
    return to_return;
}

static int tunnel_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
                           const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                           BN_MONT_CTX *m_ctx)
{
    return tunnel_mod_exp(r, a, p, m, ctx);
}
#  endif

#  ifndef OPENSSL_NO_RSA
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int tunnel_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return tunnel_mod_exp(r, a, p, m, ctx);
}
#  endif

#  ifndef OPENSSL_NO_DH
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int tunnel_mod_exp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                          BN_MONT_CTX *m_ctx)
{
    return tunnel_mod_exp(r, a, p, m, ctx);
}
#  endif

static TUNNEL_RV tunnel_get_connection(TUNNEL_CONNECTION_HNDL_PTR phConnection)
{
    int count;
    TUNNEL_RV rv = TUNNEL_R_OK;

    /*
     * Get the current process id
     */
    pid_t curr_pid;

    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);

    curr_pid = getpid();

    /*
     * Check if this is the first time this is being called from the current
     * process
     */
    if (recorded_pid != curr_pid) {
        /*
         * Remember our pid so we can check if we're in a new process
         */
        recorded_pid = curr_pid;

        /*
         * Call Finalize to make sure we have not inherited some data from a
         * parent process
         */
        p_TUNNEL_Finalize();

        /*
         * Initialise the TUNNEL API
         */
        rv = p_TUNNEL_Initialize(NULL);

        if (rv != TUNNEL_R_OK) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_GET_CONNECTION, TUNNELHK_R_INIT_FAILURE);
            recorded_pid = 0;
            goto end;
        }

        /*
         * Set the TUNNEL big num call back functions
         */
        rv = p_TUNNEL_SetBNCallBacks(&GetBigNumSize, &MakeTUNNELBigNum,
                                  &ConvertTUNNELBigNum);

        if (rv != TUNNEL_R_OK) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_GET_CONNECTION,
                     TUNNELHK_R_SETBNCALLBACK_FAILURE);
            recorded_pid = 0;
            goto end;
        }
#  ifdef TUNNELRAND
        /*
         * Reset the rand byte count
         */
        rand_block_bytes = 0;
#  endif

        /*
         * Init the structures
         */
        for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
            tunnel_app_conn_table[count].conn_state = NotConnected;
            tunnel_app_conn_table[count].conn_hndl = 0;
        }

        /*
         * Open a connection
         */
        rv = p_TUNNEL_OpenConnection(phConnection);

        if (rv != TUNNEL_R_OK) {
            TUNNELHKerr(TUNNELHK_F_TUNNEL_GET_CONNECTION, TUNNELHK_R_UNIT_FAILURE);
            recorded_pid = 0;
            goto end;
        }

        tunnel_app_conn_table[0].conn_state = InUse;
        tunnel_app_conn_table[0].conn_hndl = *phConnection;
        goto end;
    }
    /*
     * Check the existing connections to see if we can find a free one
     */
    for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
        if (tunnel_app_conn_table[count].conn_state == Connected) {
            tunnel_app_conn_table[count].conn_state = InUse;
            *phConnection = tunnel_app_conn_table[count].conn_hndl;
            goto end;
        }
    }
    /*
     * If no connections available, we're going to have to try to open a new
     * one
     */
    for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
        if (tunnel_app_conn_table[count].conn_state == NotConnected) {
            /*
             * Open a connection
             */
            rv = p_TUNNEL_OpenConnection(phConnection);

            if (rv != TUNNEL_R_OK) {
                TUNNELHKerr(TUNNELHK_F_TUNNEL_GET_CONNECTION, TUNNELHK_R_UNIT_FAILURE);
                goto end;
            }

            tunnel_app_conn_table[count].conn_state = InUse;
            tunnel_app_conn_table[count].conn_hndl = *phConnection;
            goto end;
        }
    }
    rv = TUNNEL_R_GENERAL_ERROR;
 end:
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return rv;
}

static TUNNEL_RV tunnel_return_connection(TUNNEL_CONNECTION_HNDL hConnection)
{
    int count;

    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);

    /*
     * Find the connection item that matches this connection handle
     */
    for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
        if (tunnel_app_conn_table[count].conn_hndl == hConnection) {
            tunnel_app_conn_table[count].conn_state = Connected;
            break;
        }
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);

    return TUNNEL_R_OK;
}

static TUNNEL_RV tunnel_close_connection(TUNNEL_CONNECTION_HNDL hConnection)
{
    int count;
    TUNNEL_RV rv = TUNNEL_R_OK;

    CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);

    /*
     * Find the connection item that matches this connection handle
     */
    for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
        if (tunnel_app_conn_table[count].conn_hndl == hConnection) {
            rv = p_TUNNEL_CloseConnection(tunnel_app_conn_table[count].conn_hndl);
            if (rv != TUNNEL_R_OK)
                goto end;
            tunnel_app_conn_table[count].conn_state = NotConnected;
            tunnel_app_conn_table[count].conn_hndl = 0;
            break;
        }
    }

 end:
    CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return rv;
}

static TUNNEL_RV tunnel_close_all_connections(int use_engine_lock, int *in_use)
{
    int count;
    TUNNEL_RV rv = TUNNEL_R_OK;

    *in_use = 0;
    if (use_engine_lock)
        CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
    for (count = 0; count < MAX_PROCESS_CONNECTIONS; count++) {
        switch (tunnel_app_conn_table[count].conn_state) {
        case Connected:
            rv = p_TUNNEL_CloseConnection(tunnel_app_conn_table[count].conn_hndl);
            if (rv != TUNNEL_R_OK)
                goto end;
            tunnel_app_conn_table[count].conn_state = NotConnected;
            tunnel_app_conn_table[count].conn_hndl = 0;
            break;
        case InUse:
            (*in_use)++;
            break;
        case NotConnected:
            break;
        }
    }
 end:
    if (use_engine_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
    return rv;
}

/*
 * BigNum call back functions, used to convert OpenSSL bignums into TUNNEL
 * bignums. Note only 32bit Openssl build support
 */

static TUNNEL_RV GetBigNumSize(TUNNEL_VOID_PTR ArbBigNum, TUNNEL_U32 *BigNumSize)
{
    BIGNUM *bn;

    /*
     * Cast the ArbBigNum pointer to our BIGNUM struct
     */
    bn = (BIGNUM *)ArbBigNum;

#  ifdef SIXTY_FOUR_BIT_LONG
    *BigNumSize = bn->top << 3;
#  else
    /*
     * Size of the bignum in bytes is equal to the bn->top (no of 32 bit
     * words) multiplies by 4
     */
    *BigNumSize = bn->top << 2;
#  endif

    return TUNNEL_R_OK;
}

static TUNNEL_RV MakeTUNNELBigNum(TUNNEL_VOID_PTR ArbBigNum, TUNNEL_U32 BigNumSize,
                            unsigned char *TUNNEL_BigNum)
{
    BIGNUM *bn;

#  ifndef SIXTY_FOUR_BIT_LONG
    unsigned char *buf;
    int i;
#  endif

    /*
     * Cast the ArbBigNum pointer to our BIGNUM struct
     */
    bn = (BIGNUM *)ArbBigNum;

#  ifdef SIXTY_FOUR_BIT_LONG
    memcpy(TUNNEL_BigNum, bn->d, BigNumSize);
#  else
    /*
     * Must copy data into a (monotone) least significant byte first format
     * performing endian conversion if necessary
     */
    for (i = 0; i < bn->top; i++) {
        buf = (unsigned char *)&bn->d[i];

        *((TUNNEL_U32 *)TUNNEL_BigNum) = (TUNNEL_U32)
            ((unsigned)buf[1] << 8 | buf[0]) |
            ((unsigned)buf[3] << 8 | buf[2]) << 16;

        TUNNEL_BigNum += 4;
    }
#  endif

    return TUNNEL_R_OK;
}

/*
 * Turn an TUNNEL Big Num back to a user big num
 */
static TUNNEL_RV ConvertTUNNELBigNum(void *ArbBigNum, TUNNEL_U32 BigNumSize,
                               unsigned char *TUNNEL_BigNum)
{
    BIGNUM *bn;
#  ifndef SIXTY_FOUR_BIT_LONG
    int i;
#  endif

    bn = (BIGNUM *)ArbBigNum;

    /*
     * Expand the result bn so that it can hold our big num. Size is in bits
     */
    bn_expand(bn, (int)(BigNumSize << 3));

#  ifdef SIXTY_FOUR_BIT_LONG
    bn->top = BigNumSize >> 3;

    if ((BigNumSize & 7) != 0)
        bn->top++;

    memset(bn->d, 0, bn->top << 3);

    memcpy(bn->d, TUNNEL_BigNum, BigNumSize);
#  else
    bn->top = BigNumSize >> 2;

    for (i = 0; i < bn->top; i++) {
        bn->d[i] = (TUNNEL_U32)
            ((unsigned)TUNNEL_BigNum[3] << 8 | TUNNEL_BigNum[2]) << 16 |
            ((unsigned)TUNNEL_BigNum[1] << 8 | TUNNEL_BigNum[0]);
        TUNNEL_BigNum += 4;
    }
#  endif

    return TUNNEL_R_OK;
}

# endif                         /* !OPENSSL_NO_HW_TUNNEL */
#endif                          /* !OPENSSL_NO_HW */
