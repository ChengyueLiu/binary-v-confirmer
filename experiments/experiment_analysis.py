from dataclasses import dataclass

from loguru import logger


@dataclass
class Analysis:
    over_filter_count: int = 0
    model_1_find_count: int = 0
    model_1_2_find_count: int = 0
    model_1_2_precisely_find_count: int = 0
    model_3_find_count: int = 0
    tp: int = 0  # True Positives
    fp: int = 0  # False Positives
    tn: int = 0  # True Negatives
    fn: int = 0  # False Negatives

    @property
    def total(self):
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self):
        return self.tp / (self.tp + self.fp) if self.tp + self.fp > 0 else 0

    @property
    def recall(self):
        return self.tp / (self.tp + self.fn) if self.tp + self.fn > 0 else 0

    @property
    def f1(self):
        precision = self.precision
        recall = self.recall
        return 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0

    @property
    def accuracy(self):
        total = self.total
        return (self.tp + self.tn) / total if total > 0 else 0

    @property
    def specificity(self):
        return self.tn / (self.tn + self.fp) if self.tn + self.fp > 0 else 0

    @property
    def error_rate(self):
        total = self.total
        return (self.fp + self.fn) / total if total > 0 else 0

    @property
    def mcc(self):
        # Matthews Correlation Coefficient calculation
        numerator = (self.tp * self.tn - self.fp * self.fn)
        denominator = ((self.tp + self.fp) * (self.tp + self.fn) *
                       (self.tn + self.fp) * (self.tn + self.fn)) ** 0.5
        return numerator / denominator if denominator != 0 else 0

    def print_analysis_result(self, tc_count: int):
        logger.info(f"test result:")
        logger.info(f"\ttc count: {tc_count}")
        logger.info(
            f"over filter count: {self.over_filter_count}, {round((self.over_filter_count / tc_count) * 100, 2)}%")
        logger.info(
            f"model 1 find count: {self.model_1_find_count}, {round((self.model_1_find_count / tc_count) * 100, 2)}%, {round((self.model_1_find_count / (tc_count - self.over_filter_count)) * 100, 2)}%")
        logger.info(
            f"model 1 and 2 find count: {self.model_1_2_find_count}, {round((self.model_1_2_find_count / tc_count) * 100, 2)}%, {round((self.model_1_2_find_count / self.model_1_find_count) * 100, 2)}%")
        logger.info(
            f"model 1 and 2 precisely find count: {self.model_1_2_precisely_find_count}, {round((self.model_1_2_precisely_find_count / tc_count) * 100, 2)}, {round((self.model_1_2_precisely_find_count / self.model_1_2_find_count) * 100, 2)}%")
        logger.info(
            f"model 3 find count: {self.model_3_find_count}, {round((self.model_3_find_count / tc_count) * 100, 2)}%, {round((self.model_3_find_count / self.model_1_2_find_count) * 100, 2)}%")

        logger.info(f"\ttp: {self.tp}, fp: {self.fp}, tn: {self.tn}, fn: {self.fn}")
        logger.info(f"\tprecision: {self.precision}")
        logger.info(f"\trecall: {self.recall}")
        logger.info(f"\tf1: {self.f1}")
        logger.info(f"\taccuracy: {self.accuracy}")
