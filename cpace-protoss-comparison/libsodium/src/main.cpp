#include "logger.hpp"
#include "protoss_protocol.hpp"

int main()
{
    if (sodium_init() < 0)
    {
        Logger::get_instance().log(LoggingKeyword::ERROR, "libsodium init failed");
        return 1;
    }

    Logger &logger = Logger::get_instance();
    std::string password = "SharedPassword";
    std::vector<unsigned char> P_i = {0x00};
    std::vector<unsigned char> P_j = {0x01};

    try
    {
        logger.log(LoggingKeyword::INFO, "Step One Execution - Init");
        ReturnTypeInit res_init = Init(password, P_i, P_j);
        std::vector<unsigned char> I = res_init.I;
        ProtossState protoss_state = res_init.protoss_state;

        logger.log(LoggingKeyword::INFO, "Step Two Execution - RspDer");
        ReturnTypeRspDer res_rspDer = RspDer(password, P_i, P_j, I);
        std::vector<unsigned char> R = res_rspDer.R;
        std::vector<unsigned char> session_key_j = res_rspDer.getSessionKey();

        logger.log(LoggingKeyword::INFO, "Step Three Execution - Der");
        std::vector<unsigned char> session_key_i = Der(password, protoss_state, R);

        bool match = (session_key_i == session_key_j);
        logger.log(LoggingKeyword::INFO, "Session keys " + std::string(match ? "match." : "do NOT match."));
        logger.log(LoggingKeyword::INFO, "Bit length of I " + std::to_string(get_bit_length(I)));
        logger.log(LoggingKeyword::INFO, "Bit length of I " + std::to_string(get_bit_length(R)));
    }
    catch (const std::exception &e)
    {
        logger.log(LoggingKeyword::ERROR, std::string("Exception: ") + e.what());
        return 1;
    }

    return 0;
}
