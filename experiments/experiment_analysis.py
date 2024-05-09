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
        if tc_count == 0:
            logger.error("tc_count is zero, cannot perform calculations")
            return

        logger.info("Test result:")
        logger.info(f"\t                          tc count: {tc_count}")

        model_1_percentage = round((self.model_1_find_count / tc_count) * 100, 2)
        logger.info(f"\t                model 1 find count: {self.model_1_find_count}, {model_1_percentage}%")

        model_1_2_percentage = round((self.model_1_2_find_count / tc_count) * 100, 2)
        model_1_2_relative = round((self.model_1_2_find_count / self.model_1_find_count) * 100,
                                   2) if self.model_1_find_count else 0
        logger.info(
            f"\t          model 1 and 2 find count: {self.model_1_2_find_count}, {model_1_2_percentage}%, {model_1_2_relative}%")

        model_1_2_precise_percentage = round((self.model_1_2_precisely_find_count / tc_count) * 100, 2)
        model_1_2_precise_relative = round((self.model_1_2_precisely_find_count / self.model_1_find_count) * 100,
                                           2) if self.model_1_find_count else 0
        model_1_2_precise_relative2 = round((self.model_1_2_precisely_find_count / self.model_1_2_find_count) * 100,
                                            2) if self.model_1_2_find_count else 0
        logger.info(
            f"\tmodel 1 and 2 precisely find count: {self.model_1_2_precisely_find_count}, {model_1_2_precise_percentage}%, {model_1_2_precise_relative}%, {model_1_2_precise_relative2}%")

        model_3_percentage = round((self.model_3_find_count / tc_count) * 100, 2)
        model_3_relative = round((self.model_3_find_count / self.model_1_find_count) * 100,
                                 2) if self.model_1_find_count else 0
        model_3_relative2 = round((self.model_3_find_count / self.model_1_2_find_count) * 100,
                                  2) if self.model_1_2_find_count else 0
        model_3_relative3 = round((self.model_3_find_count / self.model_1_2_precisely_find_count) * 100,
                                  2) if self.model_1_2_precisely_find_count else 0
        logger.info(
            f"\t                model 3 find count: {self.model_3_find_count}, {model_3_percentage}%, {model_3_relative}%, {model_3_relative2}%, {model_3_relative3}%")

        logger.info(f"\ttp: {self.tp}, fp: {self.fp}, tn: {self.tn}, fn: {self.fn}")
        logger.info(f"\tprecision: {self.precision}")
        logger.info(f"\t   recall: {self.recall}")
        logger.info(f"\t       f1: {self.f1}")
        logger.info(f"\t accuracy: {self.accuracy}")
