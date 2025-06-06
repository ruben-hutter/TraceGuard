import subprocess
import time
import webbrowser
import sys

# --- Configuration ---
# Path to your analysis script
ANALYSIS_SCRIPT = 'scripts/main.py'
# Path to the binary you want to analyze
BINARY_PATH = 'examples/program1' # <-- IMPORTANT: Change this to your target binary
# Arguments for your analysis script
# Add other arguments like --meta, --verbose, etc.
ANALYSIS_ARGS = [
    BINARY_PATH,
    '--meta',
    'examples/program1.meta',
    '--verbose'
]
# URL for the Schnauzer web UI
VIZ_URL = 'http://127.0.0.1:8080'


def main():
    """
    Orchestrates starting the Schnauzer server, running the analysis,
    and cleaning up afterwards.
    """
    server_process = None
    try:
        # 1. Start the schnauzer-server in the background
        print("Starting schnauzer-server...")
        # Use shell=True on Windows if 'schnauzer-server' is a .bat or .cmd file
        server_process = subprocess.Popen(['schnauzer-server'])

        # 2. Wait for the server to initialize
        print("Waiting for server to start...")
        time.sleep(3) # Adjust if the server takes longer to start

        # 3. Open the web browser
        print(f"Opening browser at {VIZ_URL}")
        webbrowser.open(VIZ_URL)

        # 4. Run your analysis script
        print(f"Running analysis on {BINARY_PATH}...")
        command = [sys.executable, ANALYSIS_SCRIPT] + ANALYSIS_ARGS
        # The analysis script runs in the foreground.
        # The wrapper will wait here until it completes.
        subprocess.run(command, check=True)

        print("Analysis finished successfully.")

    except subprocess.CalledProcessError:
        print("\nAnalysis script failed.", file=sys.stderr)
    except FileNotFoundError:
        print("\nError: 'schnauzer-server' command not found.", file=sys.stderr)
        print("Please ensure Schnauzer is installed and in your system's PATH.", file=sys.stderr)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
    finally:
        # 5. Stop the server process
        if server_process:
            print("Shutting down schnauzer-server...")
            server_process.terminate()
            server_process.wait()
            print("Server shut down.")

if __name__ == '__main__':
    main()
