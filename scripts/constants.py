# Logging formats
DEBUG_LOG_FORMAT = "[%(levelname)s] - %(filename)s:%(lineno)d - %(message)s"
INFO_LOG_FORMAT = "[%(levelname)s] - %(message)s"

# Regular expressions for matching function names and taint sources
INPUT_FUNCTION_NAMES = {"fgets", "gets", "scanf", "read", "recv", "fread"}
COMMON_LIBC_FUNCTIONS = {
    "printf",
    "scanf",
    "sprintf",
    "sscanf",
    "fprintf",
    "fscanf",
    "malloc",
    "free",
    "calloc",
    "realloc",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strcmp",
    "strncmp",
    "strlen",
    "strchr",
    "strrchr",
    "strstr",
    "strtok",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "rewind",
    "exit",
    "abort",
    "puts",
    "gets",
    "fgets",
    "fputs",
}
CRITICAL_SINK_FUNCTIONS = {
    "printf",
    "sprintf",
    "strcpy",
    "strcat",
    "system",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "gets",
    "strcpy_s",
}

# Taint scoring constants
TAINT_SCORE_INPUT_FUNCTION = 15.0
TAINT_SCORE_INPUT_HOOK_BONUS = 5.0
TAINT_SCORE_TAINTED_CALL = 8.0
TAINT_SCORE_FUNCTION_CALL = 0.1
TAINT_SCORE_DECAY_FACTOR = 0.98
TAINT_SCORE_MINIMUM_TAINTED = 3.0

# Architecture-specific constants
AMD64_ARGUMENT_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
AMD64_RETURN_REGISTER = "rax"
X86_ARGUMENT_REGISTERS = ["eax", "ecx", "edx"]  # Simplified for demonstration
X86_RETURN_REGISTER = "eax"

# Analysis limits
DEFAULT_BUFFER_SIZE = 128
MAX_TAINT_SIZE_BYTES = 256
DEFAULT_LOOP_LIMIT = 1000
