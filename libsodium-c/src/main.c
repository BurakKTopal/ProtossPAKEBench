
#include "logger.h"
#include "protoss_protocol.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    if (sodium_init() < 0)
    {
        logger_log(LOG_ERROR, "libsodium init failed");
        logger_flush();
        return 1;
    }

    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    ReturnTypeInit res_init;
    ReturnTypeRspDer res_rspder;
    unsigned char session_key_i[PROTOSS_SESSION_KEY_LEN];

    logger_log(LOG_INFO, "Step One Execution - Init");
    if (Init(&res_init, password, strlen(password), P_i, 1, P_j, 1) != 0)
    {
        logger_log(LOG_ERROR, "Init failed");
        logger_flush();
        return 1;
    }

    logger_log(LOG_INFO, "Step Two Execution - RspDer");
    if (RspDer(&res_rspder, password, strlen(password),
               P_i, 1, P_j, 1, res_init.I) != 0)
    {
        logger_log(LOG_ERROR, "RspDer failed");
        logger_flush();
        return 1;
    }

    logger_log(LOG_INFO, "Step Three Execution - Der");
    if (Der(session_key_i, &res_init.state, res_rspder.R) != 0)
    {
        logger_log(LOG_ERROR, "Der failed");
        logger_flush();
        return 1;
    }

    int match = (memcmp(session_key_i, res_rspder.K, PROTOSS_SESSION_KEY_LEN) == 0);
    logger_log(LOG_INFO, match ? "Session keys match." : "Session keys do NOT match.");
    printf("Session keys %s\n", match ? "match." : "do NOT match.");

    logger_flush();
    return 0;
}
