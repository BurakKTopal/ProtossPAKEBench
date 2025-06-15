#![forbid(unsafe_code)]

use protoss_rust::{
    init, rsp_der, der,
    SESSION_ID_BYTES,
};
use protoss_rust::logger::{Logger, LoggingKeyword};
use hex::encode;

fn main() {
    // Initialize logger
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "Protoss Protocol Demo Starting...");
    }

    println!("Protoss Protocol Library");
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "Protoss Protocol Library");
    }

    println!("=======================");
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "=======================");
    }

    // Run a simple demo
    let password = "my_secure_password";
    let p_i = [1u8; SESSION_ID_BYTES];
    let mut p_j = [2u8; SESSION_ID_BYTES];

    // Step 1: Init
    let init_result = init(password, &p_i, &mut p_j).unwrap();
    let i = init_result.i;
    println!("Init phase completed");
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "Init phase completed");
    }

    // Step 2: Responder derivation
    let rsp_der_result = rsp_der(password, &p_i, &mut p_j, i).unwrap();
    let r = rsp_der_result.r;
    let k1 = rsp_der_result.k;
    println!("RspDer phase completed");
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "RspDer phase completed");
    }

    // Step 3: Derivation
    let k2 = der(password, init_result.state, r).unwrap();
    println!("Der phase completed");
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "Der phase completed");
    }

    // Verify keys match
    let match_result = k1 == k2;
    println!("Session keys match: {}", match_result);
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, &format!("Session keys match: {}", match_result));
    }

    println!("Session key: {}", encode(k1));
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, &format!("Session key: {}", encode(k1)));
    }

    // For Windows, prevent console from closing immediately
    println!("\nPress Enter to exit...");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).unwrap();

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::INFO, "Protoss Protocol Demo Completed");
    }
}
