from bintools.general.normalize import normalize_src_lines


def count_function_effective_lines(lines):
    lines = normalize_src_lines(lines)
    start_index = 0
    for i, line in enumerate(lines):
        if "{" in line:
            start_index = i
            break
    count = 0
    for line in lines[start_index:]:
        if len(line.split()) > 1 or len(line.strip()) > 10:
            count += 1
    return count
