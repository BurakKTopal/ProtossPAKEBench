from logger import Logger, LoggingKeyword
from protoss_protocol import Init, RspDer, Der

def main():
    print("Starting Protoss protocol...")
    logger = Logger.get_instance()
    password = "SharedPassword"
    P_i = b'\x00'
    P_j = b'\x01'

    try:
        print("Step 1: Init phase...")
        logger.log(LoggingKeyword.INFO, "Step One Execution - Init")
        res_init = Init(password, P_i, P_j)
        I = res_init.I
        protoss_state = res_init.protoss_state

        print("Step 2: RspDer phase...")
        logger.log(LoggingKeyword.INFO, "Step Two Execution - RspDer")
        res_rspDer = RspDer(password, P_i, P_j, I)
        R = res_rspDer.R
        session_key_j = res_rspDer.get_session_key()

        print("Step 3: Der phase...")
        logger.log(LoggingKeyword.INFO, "Step Three Execution - Der")
        session_key_i = Der(password, protoss_state, R)

        match = (session_key_i == session_key_j)
        status = "match" if match else "do NOT match"
        print(f"Session keys {status}.")
        logger.log(LoggingKeyword.INFO, f"Session keys {status}.")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        logger.log(LoggingKeyword.ERROR, f"Exception: {str(e)}")
        logger.save_logs()
        return 1

    print("Protocol completed successfully!")
    logger.save_logs()
    return 0

if __name__ == "__main__":
    main() 