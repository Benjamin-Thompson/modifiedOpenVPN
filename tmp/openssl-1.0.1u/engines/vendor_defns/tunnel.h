/*
 * This header declares the necessary definitions for using the
 * exponentiation acceleration capabilities, and rnd number generation of the
 * TUNNEL card.
 */

/*
 *
 * Some TUNNEL defines
 *
 */

/*
 * Successful return value
 */
#define TUNNEL_R_OK                                0x00000000

/*
 * Miscelleanous unsuccessful return value
 */
#define TUNNEL_R_GENERAL_ERROR                     0x10000001

/*
 * Insufficient host memory
 */
#define TUNNEL_R_HOST_MEMORY                       0x10000002

#define TUNNEL_R_FUNCTION_FAILED                   0x10000006

/*
 * Invalid arguments in function call
 */
#define TUNNEL_R_ARGUMENTS_BAD                     0x10020000

#define TUNNEL_R_NO_TARGET_RESOURCES                               0x10030000

/*
 * Error occuring on socket operation
 */
#define TUNNEL_R_SOCKERROR                                                 0x10000010

/*
 * Socket has been closed from the other end
 */
#define TUNNEL_R_SOCKEOF                                                   0x10000011

/*
 * Invalid handles
 */
#define TUNNEL_R_CONNECTION_HANDLE_INVALID         0x100000B3

#define TUNNEL_R_TRANSACTION_HANDLE_INVALID                0x10040000

/*
 * Transaction has not yet returned from accelerator
 */
#define TUNNEL_R_TRANSACTION_NOT_READY                             0x00010000

/*
 * There is already a thread waiting on this transaction
 */
#define TUNNEL_R_TRANSACTION_CLAIMED                               0x10050000

/*
 * The transaction timed out
 */
#define TUNNEL_R_TIMED_OUT                                                 0x10060000

#define TUNNEL_R_FXN_NOT_IMPLEMENTED                               0x10070000

#define TUNNEL_R_TARGET_ERROR                                              0x10080000

/*
 * Error in the TUNNEL daemon process
 */
#define TUNNEL_R_DAEMON_ERROR                                              0x10090000

/*
 * Invalid ctx id
 */
#define TUNNEL_R_INVALID_CTX_ID                                    0x10009000

#define TUNNEL_R_NO_KEY_MANAGER                                    0x1000a000

/*
 * Error obtaining a mutex
 */
#define TUNNEL_R_MUTEX_BAD                         0x000001A0

/*
 * Fxn call before TUNNEL_Initialise ot after TUNNEL_Finialise
 */
#define TUNNEL_R_TUNNELAPI_NOT_INITIALIZED                    0x10000190

/*
 * TUNNEL_Initialise has already been called
 */
#define TUNNEL_R_TUNNELAPI_ALREADY_INITIALIZED                0x10000191

/*
 * Maximum number of connections to daemon reached
 */
#define TUNNEL_R_NO_MORE_CONNECTION_HNDLS                  0x10000200

/*
 *
 * Some TUNNEL Type definitions
 *
 */

/* an unsigned 8-bit value */
typedef unsigned char TUNNEL_U8;

/* an unsigned 8-bit character */
typedef char TUNNEL_CHAR;

/* a BYTE-sized Boolean flag */
typedef TUNNEL_U8 TUNNEL_BBOOL;

/*
 * Unsigned value, at least 16 bits long
 */
typedef unsigned short TUNNEL_U16;

/* an unsigned value, at least 32 bits long */
#ifdef SIXTY_FOUR_BIT_LONG
typedef unsigned int TUNNEL_U32;
#else
typedef unsigned long TUNNEL_U32;
#endif

#ifdef SIXTY_FOUR_BIT_LONG
typedef unsigned long TUNNEL_U64;
#else
typedef struct {
    unsigned long l1, l2;
} TUNNEL_U64;
#endif

/* at least 32 bits; each bit is a Boolean flag */
typedef TUNNEL_U32 TUNNEL_FLAGS;

typedef TUNNEL_U8 *TUNNEL_U8_PTR;
typedef TUNNEL_CHAR *TUNNEL_CHAR_PTR;
typedef TUNNEL_U32 *TUNNEL_U32_PTR;
typedef TUNNEL_U64 *TUNNEL_U64_PTR;
typedef void *TUNNEL_VOID_PTR;

/* Pointer to a TUNNEL_VOID_PTR-- i.e., pointer to pointer to void */
typedef TUNNEL_VOID_PTR *TUNNEL_VOID_PTR_PTR;

/*
 * Used to identify an TUNNEL connection handle
 */
typedef TUNNEL_U32 TUNNEL_CONNECTION_HNDL;

/*
 * Pointer to an TUNNEL connection handle
 */
typedef TUNNEL_CONNECTION_HNDL *TUNNEL_CONNECTION_HNDL_PTR;

/*
 * Used by an application (in conjunction with the apps process id) to
 * identify an individual transaction
 */
typedef TUNNEL_U32 TUNNEL_TRANSACTION_ID;

/*
 * Pointer to an applications transaction identifier
 */
typedef TUNNEL_TRANSACTION_ID *TUNNEL_TRANSACTION_ID_PTR;

/*
 * Return value type
 */
typedef TUNNEL_U32 TUNNEL_RV;

#define MAX_PROCESS_CONNECTIONS 256

#define RAND_BLK_SIZE 1024

typedef enum {
    NotConnected = 0,
    Connected = 1,
    InUse = 2
} TUNNEL_CONNECTION_STATE;

typedef struct TUNNEL_CONNECTION_ENTRY {
    TUNNEL_CONNECTION_STATE conn_state;
    TUNNEL_CONNECTION_HNDL conn_hndl;
} TUNNEL_CONNECTION_ENTRY;

typedef TUNNEL_RV t_TUNNEL_OpenConnection(TUNNEL_CONNECTION_HNDL_PTR phConnection);
typedef TUNNEL_RV t_TUNNEL_CloseConnection(TUNNEL_CONNECTION_HNDL hConnection);

typedef TUNNEL_RV t_TUNNEL_ModExp(TUNNEL_CONNECTION_HNDL hConnection,
                            TUNNEL_VOID_PTR pA, TUNNEL_VOID_PTR pP,
                            TUNNEL_VOID_PTR pN,
                            TUNNEL_VOID_PTR pResult,
                            TUNNEL_TRANSACTION_ID *pidTransID);

typedef TUNNEL_RV t_TUNNEL_ModExpCrt(TUNNEL_CONNECTION_HNDL hConnection,
                               TUNNEL_VOID_PTR pA, TUNNEL_VOID_PTR pP,
                               TUNNEL_VOID_PTR pQ,
                               TUNNEL_VOID_PTR pDmp1, TUNNEL_VOID_PTR pDmq1,
                               TUNNEL_VOID_PTR pIqmp,
                               TUNNEL_VOID_PTR pResult,
                               TUNNEL_TRANSACTION_ID *pidTransID);

#ifdef TUNNELRAND
typedef TUNNEL_RV t_TUNNEL_GenRandom(TUNNEL_CONNECTION_HNDL hConnection,
                               TUNNEL_U32 Len,
                               TUNNEL_U32 Type,
                               TUNNEL_VOID_PTR pResult,
                               TUNNEL_TRANSACTION_ID *pidTransID);
#endif

typedef TUNNEL_RV t_TUNNEL_Initialize(TUNNEL_VOID_PTR pInitArgs);
typedef TUNNEL_RV t_TUNNEL_Finalize(void);
typedef TUNNEL_RV t_TUNNEL_SetBNCallBacks(TUNNEL_RV (*GetBigNumSizeFunc)
                                     (TUNNEL_VOID_PTR ArbBigNum,
                                      TUNNEL_U32 *BigNumSize),
                                    TUNNEL_RV (*MakeTUNNELBigNumFunc) (TUNNEL_VOID_PTR
                                                                 ArbBigNum,
                                                                 TUNNEL_U32
                                                                 BigNumSize,
                                                                 unsigned char
                                                                 *TUNNEL_BigNum),
                                    TUNNEL_RV (*ConverTUNNELBigNumFunc) (void
                                                                   *ArbBigNum,
                                                                   TUNNEL_U32
                                                                   BigNumSize,
                                                                   unsigned
                                                                   char
                                                                   *TUNNEL_BigNum));
