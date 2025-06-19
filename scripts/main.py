import subprocess
import time
import webbrowser
import sys
from pathlib import Path

# Path to your analysis script
ANALYSIS_SCRIPT = "scripts/taint_se.py"
# URL for the Schnauzer web UI
VIZ_URL = "http://127.0.0.1:8080"


def main():
    """
    Orchestrates starting the Schnauzer server, running the analysis,
    and cleaning up afterwards.
    """
    if len(sys.argv) < 2:
        print("Usage: python scripts/main.py <path_to_binary> [taint_se.py_args...]", file=sys.stderr)
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if not binary_path.exists():
        print(f"Error: The specified binary path '{binary_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Collect additional arguments for the analysis script
    analysis_args = sys.argv[2:]

    command = [sys.executable, ANALYSIS_SCRIPT, str(binary_path)] + analysis_args

    server_process = None
    try:
        # 1. Start the schnauzer-server in the background
        print("Starting schnauzer-server...")
        server_process = subprocess.Popen(["schnauzer-server"])

        # 2. Wait for the server to initialize
        print("Waiting for server to start...")
        time.sleep(3)  # Adjust if the server takes longer to start

        # 3. Open the web browser
        print(f"Opening browser at {VIZ_URL}")
        webbrowser.open(VIZ_URL)

        # 4. Run your analysis script
        print(f"Running analysis on {binary_path}...")
        subprocess.run(command, check=True)

    except subprocess.CalledProcessError:
        print("Analysis script failed.", file=sys.stderr)
    except FileNotFoundError:
        print("Error: 'schnauzer-server' command not found.", file=sys.stderr)
        print(
            "Please ensure Schnauzer is installed and in your system's PATH.",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        # 5. Stop the server process
        if server_process:
            print("Shutting down schnauzer-server...")
            server_process.terminate()
            server_process.wait()
            print("Server shut down.")


if __name__ == "__main__":
    main()
