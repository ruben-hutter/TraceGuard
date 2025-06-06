from pathlib import Path


def parse_meta_file(meta_path, my_logger):
    """
    Parses a meta file to extract function names and their parameter counts.

    Args:
        meta_path (Path or str): Path to the meta file.
        my_logger (Logger): Logger instance for logging messages.

    Returns:
        dict: A dictionary mapping function names to their parameter counts.
    """
    meta_path = Path(meta_path)

    if not meta_path.exists():
        my_logger.error(f"Meta file not found: {meta_path}")
        return {}

    function_params = {}

    try:
        with meta_path.open("r") as f:
            contents = f.read()
            my_logger.info(f"Parsing meta file: {meta_path}")
            my_logger.debug(f"Meta file contents ({len(contents)} bytes)")

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

                        my_logger.debug(
                            f"Meta info: {func_name} has {param_count} parameters"
                        )
                    except Exception as e:
                        my_logger.error(f"Error parsing line {line_num}: {line} - {e}")
    except Exception as e:
        my_logger.error(f"Error parsing meta file: {e}")

    my_logger.info(f"Parsed {len(function_params)} functions from meta file")

    return function_params
