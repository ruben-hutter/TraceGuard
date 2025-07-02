import json
import argparse
import logging
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import statistics
import matplotlib.pyplot as plt

from benchmark_bin import BenchmarkRunner

class ProgressBar:
    """Simple progress bar for terminal"""
    
    def __init__(self, total, prefix='Progress', length=50):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0
        
    def update(self, current, suffix=''):
        self.current = current
        percent = (current / self.total) * 100
        filled_length = int(self.length * current // self.total)
        bar = '█' * filled_length + '-' * (self.length - filled_length)
        
        print(f'\r{self.prefix} |{bar}| {current}/{self.total} ({percent:.1f}%) {suffix}', end='', flush=True)
        
        if current == self.total:
            print()  # New line when complete

class QuietBenchmarkRunner(BenchmarkRunner):
    """Benchmark runner with suppressed output"""
    
    def __init__(self, binary_path: str, timeout: int = 120):
        super().__init__(binary_path, timeout)
        # Suppress all logging for this runner
        self.logger.setLevel(logging.CRITICAL)
        
        # Suppress angr logging
        logging.getLogger('angr').setLevel(logging.CRITICAL)
        logging.getLogger('cle').setLevel(logging.CRITICAL)
        logging.getLogger('pyvex').setLevel(logging.CRITICAL)
        
        # Suppress TraceGuard/taint_se logging - this is the key!
        logging.getLogger('taint_se').setLevel(logging.CRITICAL)
        logging.getLogger('__main__').setLevel(logging.CRITICAL)  # For taint_se.py when run as main
        
        # Also suppress the specific logger used in taint_se.py
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        try:
            # Try to import and get the actual logger from taint_se
            import taint_se
            if hasattr(taint_se, 'my_logger'):
                taint_se.my_logger.setLevel(logging.CRITICAL)
        except ImportError:
            pass
        
    def _generate_report(self, results):
        # Override to suppress the report output
        pass

class EvaluationRunner:
    """Runs multiple benchmarks and aggregates results for thesis evaluation"""
    
    def __init__(self, num_runs: int = 10, timeout: int = 120):
        self.num_runs = num_runs
        self.timeout = timeout
        self._setup_logging()
        self._setup_output_directory()
        
    def _setup_logging(self):
        """Setup minimal logging"""
        # Only log errors and critical issues
        logging.basicConfig(
            level=logging.ERROR,
            format='%(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _setup_output_directory(self):
        """Create evaluation output directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.eval_dir = Path("evaluation_results") / f"eval_{timestamp}"
        self.eval_dir.mkdir(parents=True, exist_ok=True)
    
    def _discover_test_programs(self) -> List[str]:
        """Discover test programs in benchmark/test_programs directory"""
        test_programs_dir = Path(__file__).parent / "test_programs"
        programs = []
        
        if test_programs_dir.exists():
            for file_path in test_programs_dir.iterdir():
                if file_path.is_file() and not file_path.suffix:
                    programs.append(str(file_path))
        else:
            print(f"⚠️  Test programs directory not found: {test_programs_dir}")
        
        programs = sorted(programs)
        print(f"📁 Found {len(programs)} test programs: {[Path(p).name for p in programs]}")
        return programs
    
    def run_multiple_benchmarks(self, binary_path: str) -> Dict[str, List[Dict]]:
        """Run multiple benchmark iterations for a single program"""
        program_name = Path(binary_path).stem
        
        results = {
            'traceguard': [],
            'classical': []
        }
        
        # Create progress bar for this program
        progress = ProgressBar(
            self.num_runs, 
            prefix=f'{program_name:20}',
            length=30
        )
        
        for run_num in range(self.num_runs):
            try:
                # Run single benchmark with quiet runner
                runner = QuietBenchmarkRunner(binary_path, self.timeout)
                run_results = runner.run_comparison()
                
                # Convert BenchmarkResult to dict and store
                for approach, result in run_results.items():
                    result_dict = {
                        'run_number': run_num + 1,
                        'success': result.success,
                        'execution_time': result.execution_time,
                        'states_explored': result.states_explored,
                        'basic_blocks_covered': result.basic_blocks_covered,
                        'vulnerabilities_found': result.vulnerabilities_found,
                        'time_to_first_vuln': result.time_to_first_vuln,
                        'memory_usage_mb': result.memory_usage_mb,
                        'error_message': result.error_message
                    }
                    results[approach].append(result_dict)
                
                # Update progress with timing info
                if run_results['traceguard'].success and run_results['classical'].success:
                    tg_time = run_results['traceguard'].execution_time
                    cl_time = run_results['classical'].execution_time
                    suffix = f"TG:{tg_time:.1f}s CL:{cl_time:.1f}s"
                else:
                    suffix = "Error occurred"
                
                progress.update(run_num + 1, suffix)
                
            except Exception as e:
                # Add failed results and continue
                for approach in ['traceguard', 'classical']:
                    results[approach].append({
                        'run_number': run_num + 1,
                        'success': False,
                        'execution_time': 0,
                        'states_explored': 0,
                        'basic_blocks_covered': 0,
                        'vulnerabilities_found': 0,
                        'time_to_first_vuln': None,
                        'memory_usage_mb': 0,
                        'error_message': str(e)
                    })
                
                progress.update(run_num + 1, f"FAILED: {str(e)[:20]}")
        
        return results
    
    def aggregate_results(self, results: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        """Calculate statistical aggregations"""
        aggregated = {}
        
        for approach, runs in results.items():
            successful_runs = [r for r in runs if r['success']]
            
            if not successful_runs:
                print(f"⚠️  No successful runs for {approach}")
                continue
            
            # Extract metrics
            exec_times = [r['execution_time'] for r in successful_runs]
            states = [r['states_explored'] for r in successful_runs]
            coverage = [r['basic_blocks_covered'] for r in successful_runs]
            vulns = [r['vulnerabilities_found'] for r in successful_runs]
            
            aggregated[approach] = {
                'total_runs': len(runs),
                'successful_runs': len(successful_runs),
                'success_rate': len(successful_runs) / len(runs),
                
                # Execution time stats
                'mean_execution_time': statistics.mean(exec_times),
                'std_execution_time': statistics.stdev(exec_times) if len(exec_times) > 1 else 0,
                'min_execution_time': min(exec_times),
                'max_execution_time': max(exec_times),
                'median_execution_time': statistics.median(exec_times),
                
                # State exploration stats
                'mean_states_explored': statistics.mean(states),
                'std_states_explored': statistics.stdev(states) if len(states) > 1 else 0,
                
                # Coverage stats
                'mean_coverage': statistics.mean(coverage),
                'std_coverage': statistics.stdev(coverage) if len(coverage) > 1 else 0,
                
                # Vulnerability detection stats
                'mean_vulnerabilities': statistics.mean(vulns),
                'vulnerability_detection_rate': len([r for r in successful_runs if r['vulnerabilities_found'] > 0]) / len(successful_runs),
                
                # Raw data for further analysis
                'execution_times': exec_times,
                'states_explored': states,
                'basic_blocks_covered': coverage,
                'vulnerabilities_found': vulns
            }
        
        return aggregated
    
    def save_results(self, program_name: str, raw_results: Dict, aggregated: Dict):
        """Save both raw and aggregated results"""
        # Save raw results
        raw_file = self.eval_dir / f"{program_name}_raw_results.json"
        with open(raw_file, 'w') as f:
            json.dump(raw_results, f, indent=2)
        
        # Save aggregated results
        agg_file = self.eval_dir / f"{program_name}_aggregated.json"
        
        # Convert to JSON-serializable format
        agg_serializable = {}
        for approach, stats in aggregated.items():
            agg_serializable[approach] = {k: v for k, v in stats.items() 
                                        if not isinstance(v, list)}  # Exclude raw data lists
        
        with open(agg_file, 'w') as f:
            json.dump(agg_serializable, f, indent=2)
    
    def generate_comparison_report(self, program_name: str, aggregated: Dict):
        """Generate text comparison report"""
        report = []
        report.append(f"EVALUATION REPORT: {program_name}")
        report.append("=" * 50)
        report.append(f"Number of runs: {self.num_runs}")
        report.append(f"Timeout per run: {self.timeout}s")
        report.append("")
        
        if 'traceguard' in aggregated and 'classical' in aggregated:
            tg = aggregated['traceguard']
            cl = aggregated['classical']
            
            report.append("EXECUTION TIME COMPARISON")
            report.append("-" * 30)
            report.append(f"TraceGuard:  {tg['mean_execution_time']:.3f}s ± {tg['std_execution_time']:.3f}s")
            report.append(f"Classical:   {cl['mean_execution_time']:.3f}s ± {cl['std_execution_time']:.3f}s")
            
            if cl['mean_execution_time'] > 0:
                improvement = ((cl['mean_execution_time'] - tg['mean_execution_time']) / cl['mean_execution_time']) * 100
                report.append(f"Improvement: {improvement:+.1f}%")
            
            report.append("")
            report.append("VULNERABILITY DETECTION")
            report.append("-" * 30)
            report.append(f"TraceGuard:  {tg['mean_vulnerabilities']:.1f} vulns (detection rate: {tg['vulnerability_detection_rate']:.1%})")
            report.append(f"Classical:   {cl['mean_vulnerabilities']:.1f} vulns (detection rate: {cl['vulnerability_detection_rate']:.1%})")
            
            report.append("")
            report.append("COVERAGE COMPARISON")
            report.append("-" * 30)
            report.append(f"TraceGuard:  {tg['mean_coverage']:.1f} ± {tg['std_coverage']:.1f} blocks")
            report.append(f"Classical:   {cl['mean_coverage']:.1f} ± {cl['std_coverage']:.1f} blocks")
            
            if cl['mean_coverage'] > 0:
                coverage_ratio = (tg['mean_coverage'] / cl['mean_coverage']) * 100
                report.append(f"Coverage ratio: {coverage_ratio:.1f}%")
            
            report.append("")
            report.append("SUCCESS RATES")
            report.append("-" * 30)
            report.append(f"TraceGuard:  {tg['successful_runs']}/{tg['total_runs']} ({tg['success_rate']:.1%})")
            report.append(f"Classical:   {cl['successful_runs']}/{cl['total_runs']} ({cl['success_rate']:.1%})")
        
        return "\n".join(report)
    
    def generate_simple_plot(self, program_name: str, aggregated: Dict):
        """Generate simple comparison plot"""
        if 'traceguard' not in aggregated or 'classical' not in aggregated:
            return
        
        tg = aggregated['traceguard']
        cl = aggregated['classical']
        
        _, axes = plt.subplots(1, 3, figsize=(15, 5))
        
        # Execution time comparison
        approaches = ['TraceGuard', 'Classical']
        times = [tg['mean_execution_time'], cl['mean_execution_time']]
        errors = [tg['std_execution_time'], cl['std_execution_time']]
        
        axes[0].bar(approaches, times, yerr=errors, capsize=5, alpha=0.7)
        axes[0].set_ylabel('Execution Time (s)')
        axes[0].set_title('Execution Time Comparison')
        axes[0].grid(True, alpha=0.3)
        
        # Vulnerability detection
        vuln_rates = [tg['vulnerability_detection_rate'], cl['vulnerability_detection_rate']]
        axes[1].bar(approaches, vuln_rates, alpha=0.7)
        axes[1].set_ylabel('Vulnerability Detection Rate')
        axes[1].set_title('Vulnerability Detection Rate')
        axes[1].set_ylim(0, 1.1)
        axes[1].grid(True, alpha=0.3)
        
        # Coverage comparison
        coverages = [tg['mean_coverage'], cl['mean_coverage']]
        cov_errors = [tg['std_coverage'], cl['std_coverage']]
        axes[2].bar(approaches, coverages, yerr=cov_errors, capsize=5, alpha=0.7)
        axes[2].set_ylabel('Basic Blocks Covered')
        axes[2].set_title('Coverage Comparison')
        axes[2].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plot_file = self.eval_dir / f"{program_name}_comparison.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
    
    def run_evaluation(self, programs: List[str] = []):
        """Run complete evaluation on multiple programs"""
        if not programs:
            programs = self._discover_test_programs()
        
        if not programs:
            print("❌ No test programs found!")
            return
        
        print(f"\n🚀 Starting evaluation of {len(programs)} programs with {self.num_runs} runs each")
        print(f"⏱️  Timeout per run: {self.timeout}s")
        print(f"📁 Results will be saved to: {self.eval_dir}")
        print(f"{'='*80}")
        
        all_reports = []
        start_time = time.time()
        
        for i, binary_path in enumerate(programs, 1):
            program_name = Path(binary_path).stem
            print(f"\n[{i}/{len(programs)}] {program_name}")
            
            try:
                # Run multiple benchmarks
                raw_results = self.run_multiple_benchmarks(binary_path)
                
                # Aggregate results
                aggregated = self.aggregate_results(raw_results)
                
                # Save results
                self.save_results(program_name, raw_results, aggregated)
                
                # Generate report
                report = self.generate_comparison_report(program_name, aggregated)
                all_reports.append(report)
                
                # Show quick summary
                if 'traceguard' in aggregated and 'classical' in aggregated:
                    tg = aggregated['traceguard']
                    cl = aggregated['classical']
                    improvement = ((cl['mean_execution_time'] - tg['mean_execution_time']) / cl['mean_execution_time']) * 100
                    print(f"   ⚡ Speed: {improvement:+.1f}% | 🎯 Vulns: {tg['mean_vulnerabilities']:.0f} | ✅ Success: {tg['success_rate']:.0%}")
                
                # Generate plot
                try:
                    self.generate_simple_plot(program_name, aggregated)
                except Exception as e:
                    print(f"   ⚠️  Plot generation failed: {e}")
                
            except Exception as e:
                print(f"   ❌ Failed: {e}")
                continue
        
        # Save combined report
        combined_report = "\n\n" + "="*80 + "\n\n".join(all_reports)
        report_file = self.eval_dir / "evaluation_summary.txt"
        with open(report_file, 'w') as f:
            f.write(combined_report)
        
        elapsed_time = time.time() - start_time
        print(f"\n{'='*80}")
        print(f"🎉 Evaluation complete! Total time: {elapsed_time/60:.1f} minutes")
        print(f"📊 Results saved to: {self.eval_dir}")
        print(f"📝 Summary report: {report_file}")
        print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(description="Multi-Run TraceGuard Evaluation")
    parser.add_argument('--runs', '-n', type=int, default=10, 
                       help='Number of runs per program (default: 10)')
    parser.add_argument('--timeout', '-t', type=int, default=120,
                       help='Timeout per run in seconds (default: 120)')
    parser.add_argument('--programs', nargs='+',
                       help='Specific programs to evaluate (default: auto-discover)')
    
    args = parser.parse_args()
    
    # Run evaluation
    evaluator = EvaluationRunner(num_runs=args.runs, timeout=args.timeout)
    evaluator.run_evaluation(args.programs or [])

if __name__ == "__main__":
    main()
