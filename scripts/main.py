#!/usr/bin/env python3
"""
Simple taint analyzer that uses SimProcedures to implement function skipping.
Functions like _start, main, and input functions are always executed.
"""

import sys
from core import analyze


if __name__ == "__main__":
    import argparse

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Analyze binary using taint analysis")
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("--quiet", action="store_true", help="Reduce output verbosity")
    parser.add_argument(
        "--max-steps", type=int, default=50, help="Maximum number of simulation steps"
    )
    parser.add_argument(
        "--param",
        action="append",
        nargs=2,
        metavar=("FUNCTION", "COUNT"),
        help="Override parameter count for a function, e.g. --param helper_function 1",
    )
    parser.add_argument(
        "--meta", metavar="FILE", help="Path to meta file with function prototypes"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()
    verbose = not args.quiet or args.debug

    # Process parameter overrides
    param_overrides = {}
    if args.param:
        for func_name, count in args.param:
            try:
                param_overrides[func_name] = int(count)
                if verbose:
                    print(f"Parameter override: {func_name} has {count} parameters")
            except ValueError:
                print(f"Error: parameter count must be an integer: {count}")
                sys.exit(1)

    # Run analysis
    analyze(
        args.binary,
        verbose=verbose,
        max_steps=args.max_steps,
        param_overrides=param_overrides,
        meta_file=args.meta,
    )
