import sys
import webbrowser
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from taint_se import TraceGuard, AnalysisResult

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

def start_schnauzer_server() -> Optional[subprocess.Popen]:
    """
    Start the Schnauzer visualization server.
    
    Returns:
        Server process or None if failed to start
    """
    try:
        print("Starting schnauzer-server...")
        server_process = subprocess.Popen(
            ["schnauzer-server"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        # TODO: probably not necessary since analysis takes some time
        print("Waiting for server to start...")
        #time.sleep(3)
        
        return server_process
        
    except FileNotFoundError:
        print("Warning: 'schnauzer-server' command not found.", file=sys.stderr)
        print("Visualization will not be available.", file=sys.stderr)
        print("Please ensure Schnauzer is installed and in your system's PATH.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Failed to start schnauzer-server: {e}", file=sys.stderr)
        return None

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
    1. Schnauzer server startup
    2. Browser opening for visualization
    3. TraceGuard analysis execution
    4. Results presentation
    5. Server cleanup
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
    
    # Start Schnauzer server
    server_process = start_schnauzer_server()
    
    # TODO: maybe possible parallel to analysis?
    # Open browser for visualization (if server started successfully)
    if server_process:
        open_visualization_browser()

    try:
        trace_guard = TraceGuard(binary_path, analysis_args)
        result = trace_guard.run_analysis()
        
        print_analysis_summary(result)
        
        if result.success:
            if server_process:
                print(f"🌐 Visualization available at: {VIZ_URL}")
                print("Press Enter to shut down the visualization server...")
                input()
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if server_process:
            stop_schnauzer_server(server_process)

if __name__ == "__main__":
    main()
