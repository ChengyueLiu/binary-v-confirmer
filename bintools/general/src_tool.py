from bintools.general.normalize import normalize_src_lines


def count_function_effective_lines(lines):
    lines = normalize_src_lines(lines)
    start_index = 0
    for i, line in enumerate(lines):
        if "{" in line:
            start_index = i
            break
    return len(lines[start_index:])
