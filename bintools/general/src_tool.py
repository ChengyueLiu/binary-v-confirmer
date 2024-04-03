from bintools.general.normalize import normalize_src_lines


def analyze_src_codes(normalized_src_codes):
    start_index = 0
    for i, line in enumerate(normalized_src_codes):
        if "{" in line:
            start_index = i
            break

    function_def_line = " ".join(normalized_src_codes[:start_index])
    body_start_index = start_index + 1
    param_count = function_def_line.count(",") + 1
    return body_start_index, param_count


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
