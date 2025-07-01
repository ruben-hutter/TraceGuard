import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict

from taint_se import AnalysisResult, TraceGuard

# URL for the Schnauzer web UI
VIZ_URL = "http://127.0.0.1:8080"

def parse_args(args: list) -> Dict[str, Any]:
    """
    Parse command line arguments into a dictionary for taint_se module.
    
    Args:
        args: Command line arguments (excluding binary path)
        
    Returns:
        Dictionary of parsed arguments
    """
    parsed_args = {
        "verbose": False,
        "debug": False,
        "show_libc_prints": False,
        "show_syscall_prints": False,
        "meta_file": None,
    }
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg in ["--verbose", "-v"]:
            parsed_args["verbose"] = True
        elif arg in ["--debug", "-d"]:
            parsed_args["debug"] = True
        elif arg == "--show-libc-prints":
            parsed_args["show_libc_prints"] = True
        elif arg == "--show-syscall-prints":
            parsed_args["show_syscall_prints"] = True
        elif arg == "--meta-file" and i + 1 < len(args):
            parsed_args["meta_file"] = args[i + 1]
            i += 1  # Skip next argument
        
        i += 1
    
    return parsed_args

def check_server_ready(host: str = "127.0.0.1", port: int = 8080, timeout: float = 30.0) -> bool:
    """
    Check if server is ready to accept connections.
    
    Args:
        host: Server host
        port: Server port  
        timeout: Maximum time to wait
        
    Returns:
        True if server is ready, False otherwise
    """
    import socket
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                result = sock.connect_ex((host, port))
                if result == 0:
                    return True
        except (socket.error, OSError):
            pass
        time.sleep(0.1)
    
    return False

def start_server_and_browser_async(server_process_container: dict) -> None:
    """
    Start Schnauzer server and browser in a separate thread.
    Uses a container dict to return the process to the main thread.
    
    Args:
        server_process_container: Dict to store the server process
    """
    try:
        print("Starting schnauzer-server...")
        server_process = subprocess.Popen(
            ["schnauzer-server"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        server_process_container['process'] = server_process
        
        # Wait for server to be ready
        if check_server_ready(timeout=15.0):
            # Open browser once server is confirmed ready
            try:
                print(f"Opening browser at {VIZ_URL}")
                webbrowser.open(VIZ_URL)
            except Exception as e:
                print(f"Could not open browser: {e}", file=sys.stderr)
                print(f"Please manually navigate to {VIZ_URL}", file=sys.stderr)
        else:
            print("Warning: Server did not become ready within timeout", file=sys.stderr)
            
    except FileNotFoundError:
        print("Warning: 'schnauzer-server' command not found.", file=sys.stderr)
        print("Visualization will not be available.", file=sys.stderr)
        print("Please ensure Schnauzer is installed and in your system's PATH.", file=sys.stderr)
        server_process_container['process'] = None
    except Exception as e:
        print(f"Failed to start schnauzer-server: {e}", file=sys.stderr)
        server_process_container['process'] = None

def start_schnauzer_server() -> tuple[dict, threading.Thread]:
    """
    Start the Schnauzer visualization server in parallel.
    
    Returns:
        Tuple of (server_container, thread) where server_container will contain the process
    """
    # Container to pass server process back from thread
    server_container = {'process': None}
    
    # Start server and browser in background thread
    server_thread = threading.Thread(
        target=start_server_and_browser_async,
        args=(server_container,),
        daemon=True
    )
    server_thread.start()
    
    return server_container, server_thread

def stop_schnauzer_server(server_process: subprocess.Popen) -> None:
    """Stop the Schnauzer server process."""
    if server_process:
        print("Shutting down schnauzer-server...")
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Force killing schnauzer-server...")
            server_process.kill()
            server_process.wait()
        print("Server shut down.")

def open_visualization_browser() -> None:
    """Open the web browser for visualization."""
    try:
        print(f"Opening browser at {VIZ_URL}")
        webbrowser.open(VIZ_URL)
    except Exception as e:
        print(f"Could not open browser: {e}", file=sys.stderr)
        print(f"Please manually navigate to {VIZ_URL}", file=sys.stderr)

# TODO: eventually remove emojis
def print_analysis_summary(result: AnalysisResult) -> None:
    """Print a concise summary that complements the detailed taint_se.py logs."""
    if result.success:
        print("\n✅ Analysis completed successfully!")
        
        if result.vulnerabilities_found > 0:
            print(f"🚨 Vulnerabilities found: {result.vulnerabilities_found}")
        
        if result.taint_sources_found > 0:
            print(f"🔍 Taint sources detected: {result.taint_sources_found}")
            
        if len(result.tainted_functions) > 0:
            print(f"📊 Functions processing tainted data: {len(result.tainted_functions)}")
    else:
        print("\n❌ Analysis failed!")
        if result.error_message:
            print(f"Error: {result.error_message}")

def main():
    """
    Main orchestrator function that coordinates:
    1. Parallel Schnauzer server startup and browser opening
    2. TraceGuard analysis execution
    3. Results presentation
    4. Server cleanup
    """
    if len(sys.argv) < 2:
        print(
            "Usage: python trace_guard.py <path_to_binary> [options...]",
            file=sys.stderr,
        )
        print("\nOptions:")
        print("  --verbose, -v           Enable verbose logging")
        print("  --debug, -d             Enable debug logging")
        print("  --show-libc-prints      Show libc function call details")
        print("  --show-syscall-prints   Show system call details")
        print("  --meta-file <path>      Specify custom meta file")
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if not binary_path.exists():
        print(
            f"Error: The specified binary path '{binary_path}' does not exist.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Parse arguments
    analysis_args = parse_args(sys.argv[2:])
    
    # Start Schnauzer server and browser
    server_container, server_thread = start_schnauzer_server()

    try:
        # Run analysis while server starts up
        trace_guard = TraceGuard(binary_path, analysis_args)
        result = trace_guard.run_analysis()
        
        # Wait for server thread to complete
        server_thread.join(timeout=5.0)
        
        # Get the server process from the container
        server_process = server_container.get('process')
        
        print_analysis_summary(result)
        
        if result.success:
            if server_process:
                print(f"🌐 Visualization available at: {VIZ_URL}")
                print("Press Enter to shut down the visualization server...")
                input()
            else:
                print("Note: Visualization server could not be started.")
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        server_process = server_container.get('process')
        if server_process:
            stop_schnauzer_server(server_process)

if __name__ == "__main__":
    main()
