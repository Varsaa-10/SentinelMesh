"""
eval/statistics.py — SentinelMesh Module W9: Statistical Significance & Confidence Intervals.

Implements pre-registered statistical procedures:
1. Exact McNemar Test for paired retriever comparisons (Two-Layer vs Flat, TF-IDF vs Dense).
2. Wilson Score Confidence Intervals for binomial proportions (accuracy, error rate).
3. Bootstrap Confidence Intervals for repeated captures and latency distributions.
"""

from __future__ import annotations
import math
from typing import Tuple, List, Dict, Any, Callable
import numpy as np
from scipy import stats


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """
    Computes the Wilson score interval for a binomial proportion.
    
    Returns:
        (center_proportion, lower_bound, upper_bound)
    """
    if total == 0:
        return 0.0, 0.0, 0.0
    
    p_hat = successes / total
    z = stats.norm.ppf(1 - (1 - confidence) / 2)
    z2 = z ** 2
    
    denominator = 1 + z2 / total
    center_adj = (p_hat + z2 / (2 * total)) / denominator
    spread = (z / denominator) * math.sqrt((p_hat * (1 - p_hat) / total) + (z2 / (4 * total ** 2)))
    
    lower = max(0.0, center_adj - spread)
    upper = min(1.0, center_adj + spread)
    return p_hat, lower, upper


def exact_mcnemar_test(b: int, c: int) -> Dict[str, Any]:
    """
    Computes exact McNemar test using the binomial distribution.
    
    Contingency table for paired binary classifiers:
                    Model B Correct    Model B Incorrect
    Model A Correct        a                  b
    Model A Incorrect      c                  d
    
    b: Number of items where Model A is correct, but Model B is incorrect.
    c: Number of items where Model A is incorrect, but Model B is correct.
    
    Returns dict with p_value, statistic, and interpretation.
    """
    n = b + c
    if n == 0:
        return {
            "statistic": 0,
            "b": b,
            "c": c,
            "p_value": 1.0,
            "significant_005": False,
            "significant_001": False,
        }
    
    # Exact two-tailed binomial test under H0: p = 0.5
    # Probability of observing a difference at least as extreme as min(b, c)
    k = min(b, c)
    # scipy binomtest
    res = stats.binomtest(k, n, p=0.5, alternative="two-sided")
    p_val = float(res.pvalue)
    
    # McNemar chi-square statistic with continuity correction for reference
    chi2 = ((abs(b - c) - 1) ** 2) / n if n > 0 else 0.0
    
    return {
        "statistic": float(chi2),
        "b": b,
        "c": c,
        "p_value": p_val,
        "significant_005": p_val < 0.05,
        "significant_001": p_val < 0.01,
    }


def paired_retriever_comparison(
    ground_truth: List[str],
    predictions_a: List[str],
    predictions_b: List[str],
    name_a: str = "Retriever A",
    name_b: str = "Retriever B",
) -> Dict[str, Any]:
    """
    Compares two retrievers evaluated on the exact same set of queries.
    """
    assert len(ground_truth) == len(predictions_a) == len(predictions_b), "Lengths must match"
    
    a_corr = [p == gt for p, gt in zip(predictions_a, ground_truth)]
    b_corr = [p == gt for p, gt in zip(predictions_b, ground_truth)]
    
    a_only = sum(1 for a, b in zip(a_corr, b_corr) if a and not b)
    b_only = sum(1 for a, b in zip(a_corr, b_corr) if not a and b)
    both = sum(1 for a, b in zip(a_corr, b_corr) if a and b)
    neither = sum(1 for a, b in zip(a_corr, b_corr) if not a and not b)
    
    total = len(ground_truth)
    acc_a, a_low, a_high = wilson_score_interval(sum(a_corr), total)
    acc_b, b_low, b_high = wilson_score_interval(sum(b_corr), total)
    
    test_result = exact_mcnemar_test(a_only, b_only)
    
    return {
        "model_a": {
            "name": name_a,
            "accuracy": round(acc_a, 4),
            "ci_95": [round(a_low, 4), round(a_high, 4)],
            "correct_count": sum(a_corr),
        },
        "model_b": {
            "name": name_b,
            "accuracy": round(acc_b, 4),
            "ci_95": [round(b_low, 4), round(b_high, 4)],
            "correct_count": sum(b_corr),
        },
        "contingency": {
            "both_correct": both,
            f"{name_a}_only": a_only,
            f"{name_b}_only": b_only,
            "both_incorrect": neither,
        },
        "mcnemar": test_result,
    }


def bootstrap_ci(
    values: List[float],
    stat_func: Callable[[np.ndarray], float] = np.mean,
    n_boot: int = 10000,
    confidence: float = 0.95,
    random_seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Computes bootstrap confidence interval for a given statistic over an array.
    
    Returns:
        (sample_stat, lower_ci, upper_ci)
    """
    arr = np.array(values, dtype=float)
    if len(arr) == 0:
        return 0.0, 0.0, 0.0
    if len(arr) == 1:
        val = float(arr[0])
        return val, val, val
        
    rng = np.random.default_rng(random_seed)
    boot_stats = np.empty(n_boot)
    n = len(arr)
    
    for i in range(n_boot):
        sample = rng.choice(arr, size=n, replace=True)
        boot_stats[i] = stat_func(sample)
        
    alpha = 1 - confidence
    lower = float(np.percentile(boot_stats, 100 * (alpha / 2)))
    upper = float(np.percentile(boot_stats, 100 * (1 - alpha / 2)))
    sample_stat = float(stat_func(arr))
    return sample_stat, lower, upper
