#!/usr/bin/env python3
"""
Benchmark Script for TraceGuard vs Classical Angr
Author: Ruben Hutter
University of Basel - Bachelor Thesis

This script compares TraceGuard's taint-guided symbolic execution
against classical Angr's default exploration strategy.
"""

import os
import sys
import time
import subprocess
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any
import angr
import json

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
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def run_traceguard(self) -> BenchmarkResult:
        """Run TraceGuard analysis"""
        self.logger.info("Running TraceGuard analysis...")
        
        start_time = time.time()
        
        try:
            # Construct TraceGuard command (adjust path based on current directory)
            script_path = "scripts/taint_se.py"
            if not os.path.exists(script_path):
                script_path = "../scripts/taint_se.py"  # If running from benchmark directory
            
            cmd = [
                sys.executable,
                script_path,
                self.binary_path,
                "--verbose"
            ]
            
            # Run TraceGuard
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.timeout)
            execution_time = time.time() - start_time
            
            # Parse TraceGuard output
            result = self._parse_traceguard_output(stdout, stderr)
            
            return BenchmarkResult(
                approach="TraceGuard",
                success=process.returncode == 0,
                execution_time=execution_time,
                states_explored=result.get('states_explored', 0),
                basic_blocks_covered=result.get('basic_blocks_covered', 0),
                vulnerabilities_found=result.get('vulnerabilities_found', 0),
                time_to_first_vuln=result.get('time_to_first_vuln'),
                memory_usage_mb=result.get('memory_usage', 0),
                error_message=stderr if process.returncode != 0 else None
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            self.logger.warning(f"TraceGuard timed out after {self.timeout}s")
            return BenchmarkResult(
                approach="TraceGuard",
                success=False,
                execution_time=execution_time,
                states_explored=0,
                basic_blocks_covered=0,
                vulnerabilities_found=0,
                time_to_first_vuln=None,
                memory_usage_mb=0,
                error_message="Timeout"
            )
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"TraceGuard failed: {e}")
            return BenchmarkResult(
                approach="TraceGuard",
                success=False,
                execution_time=execution_time,
                states_explored=0,
                basic_blocks_covered=0,
                vulnerabilities_found=0,
                time_to_first_vuln=None,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def run_classical_angr(self) -> BenchmarkResult:
        """Run classical Angr analysis"""
        self.logger.info("Running Classical Angr analysis...")
        
        start_time = time.time()
        
        try:
            # Load binary with Angr
            proj = angr.Project(self.binary_path, auto_load_libs=False)
            
            # Create initial state
            state = proj.factory.entry_state()
            
            # Create simulation manager with default exploration
            simgr = proj.factory.simulation_manager(state)
            
            # Track metrics
            states_explored = 0
            basic_blocks_covered = set()
            vulnerabilities_found = 0
            time_to_first_vuln = None
            vuln_start_time = time.time()
            
            self.logger.info("Starting classical Angr exploration...")
            
            # Run exploration with timeout
            max_states = 1000  # Limit to prevent explosion
            step_count = 0
            
            while simgr.active and (time.time() - start_time) < self.timeout:
                # Step the simulation
                simgr.step()
                step_count += 1
                
                # Update metrics - ACCUMULATE states, don't overwrite
                states_explored += len(simgr.active) + len(simgr.deadended) + len(simgr.errored) + len(simgr.unconstrained)
                
                # Track basic block coverage
                for state in simgr.active + simgr.deadended:
                    if hasattr(state, 'addr'):
                        basic_blocks_covered.add(state.addr)
                
                # Check for vulnerabilities in errored states
                for errored_state in simgr.errored:
                    if self._is_vulnerability(errored_state):
                        vulnerabilities_found += 1
                        if time_to_first_vuln is None:
                            time_to_first_vuln = time.time() - vuln_start_time
                        self.logger.info(f"Found vulnerability in errored state: {errored_state.error}")
                
                # ALSO check unconstrained states - these often indicate vulnerabilities
                for unconstrained_state in simgr.unconstrained:
                    # Unconstrained states often indicate buffer overflows or similar issues
                    vulnerabilities_found += 1
                    if time_to_first_vuln is None:
                        time_to_first_vuln = time.time() - vuln_start_time
                    self.logger.info(f"Found potential vulnerability: unconstrained state at {unconstrained_state.addr:#x}")
                
                # Check for deadended states that might indicate crashes
                for deadended_state in simgr.deadended:
                    # Some vulnerabilities cause states to deadend at unusual locations
                    if hasattr(deadended_state, 'addr'):
                        addr = deadended_state.addr
                        # Check if deadended in library functions that might indicate overflow
                        if any(lib_func in str(addr) for lib_func in ['strcpy', 'printf', 'sprintf', 'strcat']):
                            vulnerabilities_found += 1
                            if time_to_first_vuln is None:
                                time_to_first_vuln = time.time() - vuln_start_time
                            self.logger.info(f"Found potential vulnerability: deadended in library function at {addr:#x}")
                
                # Limit active states to prevent explosion
                if len(simgr.active) > max_states:
                    # Keep only the first max_states
                    simgr.active = simgr.active[:max_states]
                    self.logger.warning(f"Limited active states to {max_states}")
                
                # Log progress periodically
                if step_count % 50 == 0:
                    self.logger.info(f"Step {step_count}: {len(simgr.active)} active states, "
                                   f"{len(basic_blocks_covered)} blocks covered, "
                                   f"{len(simgr.unconstrained)} unconstrained, "
                                   f"{len(simgr.errored)} errored, "
                                   f"total explored: {states_explored}")
                
                # Break if no active states
                if not simgr.active:
                    self.logger.info("No more active states, exploration complete")
                    break
            
            execution_time = time.time() - start_time
            
            # Final check for vulnerabilities in all stashes
            for errored_state in simgr.errored:
                if self._is_vulnerability(errored_state):
                    vulnerabilities_found += 1
                    if time_to_first_vuln is None:
                        time_to_first_vuln = time.time() - vuln_start_time
            
            # Count unconstrained states as potential vulnerabilities
            final_unconstrained = len(simgr.unconstrained)
            if final_unconstrained > 0:
                vulnerabilities_found += final_unconstrained
                if time_to_first_vuln is None:
                    time_to_first_vuln = time.time() - vuln_start_time
                self.logger.info(f"Found {final_unconstrained} unconstrained states (potential vulnerabilities)")
            
            self.logger.info(f"Classical Angr completed: {states_explored} states, "
                           f"{len(basic_blocks_covered)} blocks, {vulnerabilities_found} vulns, "
                           f"{final_unconstrained} unconstrained")
            
            return BenchmarkResult(
                approach="Classical Angr",
                success=True,
                execution_time=execution_time,
                states_explored=states_explored,
                basic_blocks_covered=len(basic_blocks_covered),
                vulnerabilities_found=vulnerabilities_found,
                time_to_first_vuln=time_to_first_vuln,
                memory_usage_mb=self._get_memory_usage()
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Classical Angr failed: {e}")
            return BenchmarkResult(
                approach="Classical Angr",
                success=False,
                execution_time=execution_time,
                states_explored=0,
                basic_blocks_covered=0,
                vulnerabilities_found=0,
                time_to_first_vuln=None,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def _parse_traceguard_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse TraceGuard output to extract metrics from the structured analysis results"""
        result = {
            'states_explored': 0,
            'basic_blocks_covered': 0,
            'vulnerabilities_found': 0,
            'time_to_first_vuln': None,
            'memory_usage': 0
        }
        
        # Combine stdout and stderr for parsing
        output = stdout + "\n" + stderr
        lines = output.split('\n')
        
        # Look for the structured taint analysis results section
        in_analysis_results = False
        
        for line in lines:
            line_stripped = line.strip()
            line_lower = line_stripped.lower()
            
            # Track when we're in the analysis results section
            if 'taint analysis results' in line_lower:
                in_analysis_results = True
                continue
            elif in_analysis_results and '====' in line:
                in_analysis_results = False
                continue
            
            # Parse structured analysis results
            if in_analysis_results:
                if 'functions analyzed:' in line_lower:
                    # Extract total functions as proxy for basic blocks
                    try:
                        parts = line_stripped.split(':')
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result['basic_blocks_covered'] = nums[0]
                    except (ValueError, IndexError):
                        pass
                        
                elif 'tainted functions:' in line_lower:
                    # Extract tainted function count
                    try:
                        parts = line_stripped.split(':')
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result['vulnerabilities_found'] = nums[0]
                    except (ValueError, IndexError):
                        pass
                        
                elif 'taint propagation paths:' in line_lower:
                    # Extract propagation path count as additional vulnerability indicator
                    try:
                        parts = line_stripped.split(':')
                        if len(parts) > 1:
                            nums = [int(x) for x in parts[1].split() if x.isdigit()]
                            if nums:
                                result['vulnerabilities_found'] += nums[0]
                    except (ValueError, IndexError):
                        pass
            
            # Parse simulation manager results
            elif 'states are still active' in line_lower:
                try:
                    words = line_stripped.split()
                    for word in words:
                        if word.isdigit():
                            result['states_explored'] += int(word)
                            break
                except (ValueError, IndexError):
                    pass
                    
            elif 'states reached a dead end' in line_lower:
                try:
                    words = line_stripped.split()
                    for word in words:
                        if word.isdigit():
                            result['states_explored'] += int(word)
                            break
                except (ValueError, IndexError):
                    pass
                    
            elif 'states encountered errors' in line_lower:
                try:
                    words = line_stripped.split()
                    for word in words:
                        if word.isdigit():
                            result['states_explored'] += int(word)
                            # Error states often indicate vulnerabilities
                            result['vulnerabilities_found'] += int(word)
                            break
                except (ValueError, IndexError):
                    pass
                    
            elif 'states are unconstrained' in line_lower:
                try:
                    words = line_stripped.split()
                    for word in words:
                        if word.isdigit():
                            result['states_explored'] += int(word)
                            # Unconstrained states are potential vulnerabilities
                            result['vulnerabilities_found'] += int(word)
                            break
                except (ValueError, IndexError):
                    pass
            
            # Look for specific taint detection messages
            elif 'taint_source:' in line_lower or 'input function' in line_lower:
                result['vulnerabilities_found'] += 1
                
            elif 'taint_arg:' in line_lower and 'tainted' in line_lower:
                # Tainted argument indicates vulnerability potential
                result['vulnerabilities_found'] += 1
            
            # Count unique function hooks as exploration activity
            elif 'hook #' in line_lower and 'called:' in line_lower:
                result['states_explored'] += 1
        
        # Ensure minimum values
        if result['states_explored'] == 0:
            # If no explicit states found, estimate from hook calls
            hook_count = output.lower().count('hook #')
            result['states_explored'] = max(1, hook_count)
            
        if result['basic_blocks_covered'] == 0:
            # Estimate basic blocks from function calls
            result['basic_blocks_covered'] = max(1, result['states_explored'])
        
        return result
    
    def _is_vulnerability(self, errored_state) -> bool:
        """Check if an errored state represents a vulnerability"""
        if not hasattr(errored_state, 'error'):
            return False
            
        error_str = str(errored_state.error).lower()
        
        # Look for vulnerability indicators
        vulnerability_indicators = [
            'segmentation fault',
            'segfault',
            'buffer overflow',
            'stack overflow',
            'heap overflow',
            'access violation',
            'memory error',
            'sigsegv',
            'simmemorylimitexception',
            'simstateerror',
            'simcallstackpopexception'
        ]
        
        # Also check for specific memory access patterns that might indicate overflow
        is_vuln = any(indicator in error_str for indicator in vulnerability_indicators)
        
        if is_vuln:
            self.logger.info(f"Detected potential vulnerability: {error_str}")
            
        return is_vuln
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
    
    def run_comparison(self) -> Dict[str, BenchmarkResult]:
        """Run both TraceGuard and Classical Angr and compare results"""
        self.logger.info(f"Starting benchmark comparison for {self.binary_path}")
        
        results = {}
        
        # Run TraceGuard
        traceguard_result = self.run_traceguard()
        results['traceguard'] = traceguard_result
        
        # Run Classical Angr
        classical_result = self.run_classical_angr()
        results['classical'] = classical_result
        
        # Generate comparison report
        self._generate_report(results)
        
        return results
    
    def _generate_report(self, results: Dict[str, BenchmarkResult]):
        """Generate comparison report"""
        print("\n" + "="*60)
        print("BENCHMARK RESULTS COMPARISON")
        print("="*60)
        
        traceguard = results['traceguard']
        classical = results['classical']
        
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
                time_improvement = ((classical.execution_time - traceguard.execution_time) 
                                  / classical.execution_time * 100)
                print(f"TraceGuard Time Improvement: {time_improvement:.1f}%")
            
            # State exploration efficiency
            if classical.states_explored > 0:
                state_reduction = ((classical.states_explored - traceguard.states_explored) 
                                 / classical.states_explored * 100)
                print(f"TraceGuard State Reduction: {state_reduction:.1f}%")
            
            # Vulnerability detection
            print("Vulnerability Detection:")
            print(f"  TraceGuard: {traceguard.vulnerabilities_found}")
            print(f"  Classical:  {classical.vulnerabilities_found}")
            
            # Coverage comparison
            if classical.basic_blocks_covered > 0:
                coverage_ratio = (traceguard.basic_blocks_covered / 
                                classical.basic_blocks_covered * 100)
                print(f"TraceGuard Coverage: {coverage_ratio:.1f}% of Classical")
        
        print("\n" + "="*60)
        
        # Save results to JSON
        self._save_results_json(results)
    
    def _save_results_json(self, results: Dict[str, BenchmarkResult]):
        """Save results to JSON file"""
        output_file = f"benchmark_results_{Path(self.binary_path).stem}.json"
        
        # Convert results to dict for JSON serialization
        json_results = {}
        for approach, result in results.items():
            json_results[approach] = {
                'approach': result.approach,
                'success': result.success,
                'execution_time': result.execution_time,
                'states_explored': result.states_explored,
                'basic_blocks_covered': result.basic_blocks_covered,
                'vulnerabilities_found': result.vulnerabilities_found,
                'time_to_first_vuln': result.time_to_first_vuln,
                'memory_usage_mb': result.memory_usage_mb,
                'error_message': result.error_message
            }
        
        with open(output_file, 'w') as f:
            json.dump(json_results, f, indent=2)
        
        print(f"\nResults saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark TraceGuard vs Classical Angr"
    )
    parser.add_argument(
        "binary",
        help="Path to the binary to analyze"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout in seconds (default: 120)"
    )
    
    args = parser.parse_args()
    
    # Check if binary exists
    if not os.path.exists(args.binary):
        print(f"Error: Binary {args.binary} not found!")
        sys.exit(1)
    
    # Run benchmark
    runner = BenchmarkRunner(args.binary, args.timeout)
    runner.run_comparison()


if __name__ == "__main__":
    main()
