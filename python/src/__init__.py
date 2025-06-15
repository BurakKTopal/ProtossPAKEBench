# Python Protoss Protocol package 
import sodium_bindings

# Initialize libsodium
result = sodium_bindings.sodium_init()
if result < 0:
    raise RuntimeError("Failed to initialize libsodium") 