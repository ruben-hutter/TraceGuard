import os
import sys
import time
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any
import angr
import json

# Add the scripts directory to the Python path for direct imports
script_dir = Path(__file__).parent
project_root = script_dir.parent
scripts_path = project_root / "scripts"
sys.path.insert(0, str(scripts_path))


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run"""

    approach: str
    success: bool
    execution_time: float
    states_explored: int
    basic_blocks_covered: int
    vulnerabilities_found: int
    time_to_first_vuln: Optional[float]
    memory_usage_mb: float
    error_message: Optional[str] = None


class BenchmarkRunner:
    """Main benchmark runner for comparing TraceGuard vs Classical Angr"""

    def __init__(self, binary_path: str, timeout: int = 120):
        self.binary_path = binary_path
        self.timeout = timeout
        self._setup_logging()
        self._setup_output_directory()

    def _setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def _setup_output_directory(self):
        """Create output directory for benchmark results"""
        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)
        self.logger.info(f"Results will be saved to: {self.results_dir}")

    def run_traceguard(self, quite) -> BenchmarkResult:
        """Run TraceGuard analysis using direct module import"""
        self.logger.info("Running TraceGuard analysis...")

        try:
            try:
                from taint_se import TraceGuard
            except ImportError as e:
                self.logger.error(f"Failed to import TraceGuard: {e}")
                sys.exit(1)

            # Create TraceGuard instance with appropriate arguments
            args = {
                "verbose": False,
                "debug": False,
                "meta_file": None,
                "show_libc_prints": False,
                "show_syscall_prints": False,
                "quite": quite,
            }

            # Run analysis
            trace_guard = TraceGuard(binary_path=self.binary_path, args=args)
            analysis_result = trace_guard.run_analysis(timeout=self.timeout)

            # Convert AnalysisResult to BenchmarkResult
            return BenchmarkResult(
                approach="TraceGuard",
                success=analysis_result.success,
                execution_time=analysis_result.analysis_time,
                states_explored=analysis_result.states_explored,
                basic_blocks_covered=analysis_result.basic_blocks_covered,
                vulnerabilities_found=analysis_result.vulnerabilities_found,
                time_to_first_vuln=analysis_result.time_to_first_vuln,
                memory_usage_mb=analysis_result.memory_usage_mb,
                error_message=analysis_result.error_message,
            )

        except Exception as e:
            self.logger.error(f"TraceGuard failed: {e}")
            import traceback

            traceback.print_exc()

            return BenchmarkResult(
                approach="TraceGuard",
                success=False,
                execution_time=0,
                states_explored=0,
                basic_blocks_covered=0,
                vulnerabilities_found=0,
                time_to_first_vuln=None,
                memory_usage_mb=0,
                error_message=str(e),
            )

    def _get_memory_usage(self):
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0

    def run_classical_angr(self) -> BenchmarkResult:
        """Run classical Angr analysis"""
        self.logger.info("Running Classical Angr analysis...")

        try:
            # Load binary with Angr
            proj = angr.Project(self.binary_path, auto_load_libs=False)

            # Create initial state at main function
            main_symbol = proj.loader.find_symbol("main")
            if main_symbol:
                main_addr = main_symbol.rebased_addr
            else:
                main_addr = proj.entry

            state = proj.factory.full_init_state(addr=main_addr)

            # Create simulation manager with default exploration
            simgr = proj.factory.simulation_manager(state, save_unconstrained=True)

            # Add exploration techniques for fair comparison
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))

            # Build CFG for LoopSeer
            try:
                cfg = proj.analyses.CFGFast()
                cfg.normalize()
                simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
            except Exception as e:
                self.logger.warning(f"Failed to build CFG for LoopSeer: {e}")

            simgr.use_technique(angr.exploration_techniques.DFS())

            # Track metrics
            basic_blocks_covered = set()
            vulnerabilities_found = 0
            time_to_first_vuln = None
            start_time = time.time()
            first_vuln_found = False

            self.logger.info("Starting classical Angr exploration...")

            # Create a custom step function to track vulnerabilities and metrics
            def step_with_metrics(simgr):
                nonlocal first_vuln_found, vulnerabilities_found, time_to_first_vuln, basic_blocks_covered
                
                # Perform the actual step
                simgr.step()
                
                # Track basic blocks covered
                for state in simgr.active:
                    if state.addr:
                        basic_blocks_covered.add(state.addr)

                # Check for vulnerabilities
                if not first_vuln_found:
                    new_vulnerabilities = 0

                    # Check unconstrained states (potential buffer overflows)
                    if simgr.unconstrained:
                        new_vuln_count = len(simgr.unconstrained)
                        if new_vuln_count > 0:
                            new_vulnerabilities += new_vuln_count
                            self.logger.info(f"Found {new_vuln_count} unconstrained states")

                    # Check errored states for potential vulnerabilities
                    if simgr.errored:
                        for error_record in simgr.errored:
                            error_str = str(error_record.error).lower()
                            if any(
                                vuln_indicator in error_str
                                for vuln_indicator in [
                                    "segmentation fault",
                                    "segfault",
                                    "buffer overflow",
                                    "stack overflow",
                                    "heap overflow",
                                    "access violation",
                                    "memory error",
                                    "sigsegv",
                                ]
                            ):
                                new_vulnerabilities += 1

                    # Record time to first vulnerability
                    if new_vulnerabilities > 0:
                        time_to_first_vuln = time.time() - start_time
                        first_vuln_found = True
                        vulnerabilities_found += new_vulnerabilities
                        self.logger.info(
                            f"First vulnerability found at {time_to_first_vuln:.3f}s"
                        )
                
                return simgr

            # Run simulation with proper timeout using angr's built-in mechanism
            try:
                self.logger.info(f"Running classical simulation with {self.timeout}s timeout")
                
                simgr.run(
                    step_func=step_with_metrics,
                    timeout=self.timeout,
                    step_limit=500  # Prevent infinite loops
                )
                
                success = True
                error_message = None
                self.logger.info("Classical Angr completed successfully")
                
            except angr.errors.AngrTimeoutError:
                self.logger.warning(f"TIMEOUT: Classical Angr analysis stopped after {self.timeout}s")
                success = True  # Timeout is not a failure
                error_message = f"Timeout after {self.timeout}s"

            execution_time = time.time() - start_time

            # Calculate total states explored
            total_states = (
                len(simgr.active)
                + len(simgr.deadended)
                + len(simgr.errored)
                + len(simgr.unconstrained)
            )

            self.logger.info(f"Classical Angr completed in {execution_time:.2f}s")
            self.logger.info(f"Total states: {total_states}")
            self.logger.info(f"Basic blocks covered: {len(basic_blocks_covered)}")
            self.logger.info(f"Vulnerabilities found: {vulnerabilities_found}")

            memory_usage = self._get_memory_usage()

            return BenchmarkResult(
                approach="Classical Angr",
                success=success,
                execution_time=execution_time,
                states_explored=total_states,
                basic_blocks_covered=len(basic_blocks_covered),
                vulnerabilities_found=vulnerabilities_found,
                time_to_first_vuln=time_to_first_vuln,
                memory_usage_mb=memory_usage,
                error_message=error_message,
            )

        except Exception as e:
            self.logger.error(f"Classical Angr failed: {e}")
            import traceback

            traceback.print_exc()

            return BenchmarkResult(
                approach="Classical Angr",
                success=False,
                execution_time=0,
                states_explored=0,
                basic_blocks_covered=0,
                vulnerabilities_found=0,
                time_to_first_vuln=None,
                memory_usage_mb=0,
                error_message=str(e),
            )

    def run_comparison(self, quite=True) -> Dict[str, BenchmarkResult]:
        """Run comparison between TraceGuard and Classical Angr"""
        self.logger.info(f"Starting benchmark comparison for {self.binary_path}")

        results = {}

        # Run TraceGuard
        traceguard_result = self.run_traceguard(quite=quite)
        results["traceguard"] = traceguard_result

        # Run Classical Angr
        classical_result = self.run_classical_angr()
        results["classical"] = classical_result

        # Generate comparison report
        self._generate_report(results)

        return results

    def _parse_traceguard_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse TraceGuard output to extract metrics (fallback method)"""
        result = {
            "states_explored": 0,
            "basic_blocks_covered": 0,
            "vulnerabilities_found": 0,
            "time_to_first_vuln": None,
            "memory_usage": 0,
        }

        # Combine stdout and stderr for parsing
        output = stdout + "\n" + stderr
        lines = output.split("\n")

        # Look for the structured taint analysis results section
        in_analysis_results = False

        for line in lines:
            line_stripped = line.strip()
            line_lower = line_stripped.lower()

            # Track when we're in the analysis results section
            if "taint analysis results" in line_lower:
                in_analysis_results = True
                continue
            elif in_analysis_results and "====" in line:
                in_analysis_results = False
                continue

            # Parse structured analysis results
            if in_analysis_results:
                if (
                    "functions discovered:" in line_lower
                    or "functions analyzed:" in line_lower
                ):
                    try:
                        parts = line_stripped.split(":")
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result["basic_blocks_covered"] = nums[0]
                    except (ValueError, IndexError):
                        pass

                elif "vulnerabilities found:" in line_lower:
                    try:
                        parts = line_stripped.split(":")
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result["vulnerabilities_found"] = nums[0]
                    except (ValueError, IndexError):
                        pass

                elif "states explored:" in line_lower or "total states:" in line_lower:
                    try:
                        parts = line_stripped.split(":")
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result["states_explored"] = nums[0]
                    except (ValueError, IndexError):
                        pass

            # Look for time information
            if "time to first vulnerability:" in line_lower:
                try:
                    import re

                    time_match = re.search(r"(\d+\.?\d*)\s*(?:seconds?|s)", line_lower)
                    if time_match:
                        result["time_to_first_vuln"] = float(time_match.group(1))
                except (ValueError, AttributeError):
                    pass

        return result

    def _generate_report(self, results: Dict[str, BenchmarkResult]):
        """Generate comparison report"""
        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS COMPARISON")
        print("=" * 60)

        traceguard = results["traceguard"]
        classical = results["classical"]

        print(f"\nProgram: {self.binary_path}")
        print(f"Timeout: {self.timeout}s")

        print("\n--- TraceGuard Results ---")
        print(f"Success: {traceguard.success}")
        print(f"Execution Time: {traceguard.execution_time:.2f}s")
        print(f"States Explored: {traceguard.states_explored}")
        print(f"Basic Blocks Covered: {traceguard.basic_blocks_covered}")
        print(f"Vulnerabilities Found: {traceguard.vulnerabilities_found}")
        if traceguard.time_to_first_vuln:
            print(f"Time to First Vulnerability: {traceguard.time_to_first_vuln:.2f}s")
        if traceguard.error_message:
            print(f"Error: {traceguard.error_message}")

        print("\n--- Classical Angr Results ---")
        print(f"Success: {classical.success}")
        print(f"Execution Time: {classical.execution_time:.2f}s")
        print(f"States Explored: {classical.states_explored}")
        print(f"Basic Blocks Covered: {classical.basic_blocks_covered}")
        print(f"Vulnerabilities Found: {classical.vulnerabilities_found}")
        if classical.time_to_first_vuln:
            print(f"Time to First Vulnerability: {classical.time_to_first_vuln:.2f}s")
        if classical.error_message:
            print(f"Error: {classical.error_message}")

        # Comparison analysis
        print("\n--- COMPARISON ANALYSIS ---")

        if traceguard.success and classical.success:
            # Time efficiency
            if classical.execution_time > 0:
                time_improvement = (
                    (classical.execution_time - traceguard.execution_time)
                    / classical.execution_time
                    * 100
                )
                print(f"TraceGuard Time Improvement: {time_improvement:+.1f}%")

            # State exploration efficiency
            if classical.states_explored > 0:
                state_reduction = (
                    (classical.states_explored - traceguard.states_explored)
                    / classical.states_explored
                    * 100
                )
                print(f"TraceGuard State Reduction: {state_reduction:+.1f}%")

            # Vulnerability detection
            print("Vulnerability Detection:")
            print(f"  TraceGuard: {traceguard.vulnerabilities_found}")
            print(f"  Classical:  {classical.vulnerabilities_found}")

            if traceguard.vulnerabilities_found > classical.vulnerabilities_found:
                print(
                    f"  TraceGuard found {traceguard.vulnerabilities_found - classical.vulnerabilities_found} more vulnerabilities"
                )
            elif classical.vulnerabilities_found > traceguard.vulnerabilities_found:
                print(
                    f"  Classical found {classical.vulnerabilities_found - traceguard.vulnerabilities_found} more vulnerabilities"
                )
            else:
                print("  Both approaches found the same number of vulnerabilities")

            # Coverage comparison
            if classical.basic_blocks_covered > 0:
                coverage_ratio = (
                    traceguard.basic_blocks_covered
                    / classical.basic_blocks_covered
                    * 100
                )
                print(f"TraceGuard Coverage: {coverage_ratio:.1f}% of Classical")

            # Time to first vulnerability comparison
            if traceguard.time_to_first_vuln and classical.time_to_first_vuln:
                if traceguard.time_to_first_vuln < classical.time_to_first_vuln:
                    speedup = (
                        classical.time_to_first_vuln / traceguard.time_to_first_vuln
                    )
                    print(f"TraceGuard found first vulnerability {speedup:.1f}x faster")
                else:
                    slowdown = (
                        traceguard.time_to_first_vuln / classical.time_to_first_vuln
                    )
                    print(f"Classical found first vulnerability {slowdown:.1f}x faster")

        elif traceguard.success and not classical.success:
            print("TraceGuard succeeded while Classical Angr failed")
        elif not traceguard.success and classical.success:
            print("Classical Angr succeeded while TraceGuard failed")
        else:
            print("Both approaches failed")

        print("\n" + "=" * 60)

        self._save_results_json(results)

    def _save_results_json(self, results: Dict[str, BenchmarkResult]):
        """Save results to JSON file in the results directory"""
        # Create timestamped filename to avoid overwrites
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        binary_name = Path(self.binary_path).stem
        output_file = self.results_dir / f"benchmark_{binary_name}_{timestamp}.json"

        # Convert results to dict for JSON serialization
        json_results = {
            "metadata": {
                "binary_path": str(self.binary_path),
                "binary_name": binary_name,
                "timeout": self.timeout,
                "timestamp": timestamp,
                "run_time": datetime.now().isoformat()
            },
            "results": {}
        }
        
        for approach, result in results.items():
            json_results["results"][approach] = {
                "approach": result.approach,
                "success": result.success,
                "execution_time": result.execution_time,
                "states_explored": result.states_explored,
                "basic_blocks_covered": result.basic_blocks_covered,
                "vulnerabilities_found": result.vulnerabilities_found,
                "time_to_first_vuln": result.time_to_first_vuln,
                "memory_usage_mb": result.memory_usage_mb,
                "error_message": result.error_message,
            }

        with open(output_file, "w") as f:
            json.dump(json_results, f, indent=2)

        print(f"\nResults saved to: {output_file}")
        
        # Also create a symlink to the latest result for easy access
        latest_link = self.results_dir / f"latest_{binary_name}.json"
        try:
            if latest_link.exists():
                latest_link.unlink()
            latest_link.symlink_to(output_file.name)
            print(f"Latest result symlinked as: {latest_link}")
        except OSError:
            # Symlinks might not work on all systems, just skip
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark TraceGuard vs Classical Angr"
    )
    parser.add_argument("binary", help="Path to the binary to analyze")
    parser.add_argument(
        "--timeout", type=int, default=120, help="Timeout in seconds (default: 120)"
    )

    args = parser.parse_args()

    # Check if binary exists
    if not os.path.exists(args.binary):
        print(f"Error: Binary {args.binary} not found!")
        sys.exit(1)

    # Run benchmark
    runner = BenchmarkRunner(args.binary, args.timeout)
    runner.run_comparison(quite=False)


if __name__ == "__main__":
    main()
