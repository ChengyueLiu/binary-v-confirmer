import os

from Experiment import run_experiment


def parse_file():
    results = []
    with open('score_all.csv', 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if len(line.split(',')) != 5:
                continue
            g_has_vul_func, g_has_vul, diff_line_num, vul_score, fix_score = line.split(',')
            results.append(
                (bool(g_has_vul_func), g_has_vul == 'True', int(diff_line_num), float(vul_score), float(fix_score)))
    return results


def check_results():
    results = parse_file()
    all_count = 0
    right_count = 0
    wrong_count = 0
    for g_has_vul_func, g_has_vul, diff_line_num, vul_score, fix_score in results:

        all_count += 1
        original_fix_score = fix_score
        fix_score = round(fix_score, 4)
        has_vul = vul_score > fix_score
        print(
            f"{g_has_vul_func}\t{g_has_vul}\t{diff_line_num}\t{vul_score}\t{original_fix_score}\t{fix_score}\t{has_vul}\t{has_vul == g_has_vul}")
        if g_has_vul == has_vul:
            right_count += 1
        else:
            wrong_count += 1
    right_rate = round(right_count / all_count, 4)
    print(all_count, right_count, wrong_count, right_rate)


if __name__ == '__main__':
    check_results()
