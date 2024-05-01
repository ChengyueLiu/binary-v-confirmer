import os

from Experiment import run_experiment

if __name__ == '__main__':
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    run_experiment()