import os


def parse_meta_file(meta_path, verbose=True):
    """Parse a meta file with function prototypes to get parameter counts."""
    if not os.path.exists(meta_path):
        if verbose:
            print(f"Meta file not found: {meta_path}")
        return {}

    function_params = {}

    try:
        with open(meta_path, "r") as f:
            contents = f.read()
            if verbose:
                print(f"Parsing meta file: {meta_path}")
                print(f"Meta file contents ({len(contents)} bytes):")
                print("---")
                print(contents)
                print("---")

            for line_num, line in enumerate(contents.splitlines(), 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith(("//", "#")):
                    continue

                # Remove trailing semicolon
                if line.endswith(";"):
                    line = line[:-1].strip()

                # Parse function prototype
                if "(" in line and ")" in line:
                    try:
                        # Extract function name
                        func_part = line.split("(")[0].strip()
                        func_name = func_part.split()[-1]

                        # Extract and count parameters
                        params_str = line.split("(")[1].split(")")[0].strip()
                        param_count = (
                            0
                            if not params_str or params_str.lower() == "void"
                            else len(params_str.split(","))
                        )

                        # Store result
                        function_params[func_name] = param_count

                        if verbose:
                            print(
                                f"Meta info: {func_name} has {param_count} parameters"
                            )
                    except Exception as e:
                        if verbose:
                            print(f"Error parsing line {line_num}: {line} - {e}")
    except Exception as e:
        if verbose:
            print(f"Error parsing meta file: {e}")

    if verbose:
        print(f"Parsed {len(function_params)} functions from meta file")

    return function_params
