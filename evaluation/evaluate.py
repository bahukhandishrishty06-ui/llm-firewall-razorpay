"""
PayGuard Evaluation Script
Runs the held-out test set through the firewall and computes:
- Precision, recall, F1 per attack category
- False-positive cost analysis
- Precision-recall tradeoff at multiple confidence thresholds
- Confusion matrix
- Failure case analysis

Reports honestly — no cherry-picking.
"""

import os
import sys
import json
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from firewall.input_screener import screen_input, heuristic_scan
from firewall.action_screener import screen_action
from agent.tools import seed_test_orders


def load_test_set():
    """Load the held-out test set."""
    test_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "test.json")
    if not os.path.exists(test_path):
        print("Test set not found. Generating corpus first...")
        from data.generate_attack_corpus import generate_corpus, split_corpus, save_corpus
        corpus = generate_corpus()
        train, test = split_corpus(corpus)
        save_corpus(corpus, train, test)

    with open(test_path, "r") as f:
        data = json.load(f)
    return data["examples"]


def evaluate_at_threshold(test_set, block_threshold=0.7, flag_threshold=0.4,
                          use_llm=False, verbose=False):
    """
    Run evaluation at a specific threshold setting.
    Returns detailed results per example and aggregated metrics.
    """
    results = []

    for i, example in enumerate(test_set):
        text = example["text"]
        is_malicious = example["is_malicious"]
        category = example["category"]
        example_id = example.get("id", f"ex_{i}")

        # Run input screener
        screening = screen_input(
            text=text,
            input_type=example.get("context_type", "direct_input"),
            force_llm=use_llm,
            block_threshold=block_threshold,
            flag_threshold=flag_threshold,
        )

        # Determine prediction
        predicted_malicious = screening.verdict in ("block", "flag_for_human")
        predicted_blocked = screening.verdict == "block"

        results.append({
            "id": example_id,
            "text": text[:100] + "..." if len(text) > 100 else text,
            "category": category,
            "is_malicious": is_malicious,
            "predicted_malicious": predicted_malicious,
            "predicted_blocked": predicted_blocked,
            "verdict": screening.verdict,
            "confidence": screening.confidence,
            "reason": screening.reason,
            "heuristic_score": screening.heuristic_score,
            "correct": predicted_malicious == is_malicious,
        })

        if verbose:
            status = "✓" if predicted_malicious == is_malicious else "✗"
            print(f"  {status} [{example_id}] {category}: verdict={screening.verdict} "
                  f"conf={screening.confidence:.2f} (actual={'malicious' if is_malicious else 'benign'})")

    return results


def compute_metrics(results):
    """Compute precision, recall, F1 from evaluation results."""
    # Overall metrics
    tp = sum(1 for r in results if r["is_malicious"] and r["predicted_malicious"])
    fp = sum(1 for r in results if not r["is_malicious"] and r["predicted_malicious"])
    fn = sum(1 for r in results if r["is_malicious"] and not r["predicted_malicious"])
    tn = sum(1 for r in results if not r["is_malicious"] and not r["predicted_malicious"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0

    overall = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": len(results),
    }

    # Per-category metrics
    categories = set(r["category"] for r in results)
    per_category = {}

    for cat in sorted(categories):
        cat_results = [r for r in results if r["category"] == cat]
        cat_tp = sum(1 for r in cat_results if r["is_malicious"] and r["predicted_malicious"])
        cat_fp = sum(1 for r in cat_results if not r["is_malicious"] and r["predicted_malicious"])
        cat_fn = sum(1 for r in cat_results if r["is_malicious"] and not r["predicted_malicious"])
        cat_tn = sum(1 for r in cat_results if not r["is_malicious"] and not r["predicted_malicious"])

        cat_precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0
        cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0
        cat_f1 = 2 * cat_precision * cat_recall / (cat_precision + cat_recall) if (cat_precision + cat_recall) > 0 else 0.0

        per_category[cat] = {
            "precision": round(cat_precision, 4),
            "recall": round(cat_recall, 4),
            "f1": round(cat_f1, 4),
            "tp": cat_tp, "fp": cat_fp, "fn": cat_fn, "tn": cat_tn,
            "total": len(cat_results),
        }

    return overall, per_category


def compute_fp_cost(results):
    """
    Compute false-positive cost analysis.
    Estimates the business cost of wrongly blocking legitimate requests.
    """
    # Cost model (estimated per-incident costs in ₹)
    COST_MODEL = {
        "blocked_refund_request": {
            "cost_inr": 500,
            "description": "Customer escalation to human support + potential churn",
        },
        "blocked_status_check": {
            "cost_inr": 100,
            "description": "Customer frustration, repeat contact",
        },
        "blocked_discount_request": {
            "cost_inr": 200,
            "description": "Lost sale opportunity + customer dissatisfaction",
        },
        "blocked_general_query": {
            "cost_inr": 150,
            "description": "Poor customer experience, potential churn",
        },
    }

    false_positives = [r for r in results if not r["is_malicious"] and r["predicted_malicious"]]

    total_cost = 0
    fp_details = []

    for fp in false_positives:
        text_lower = fp["text"].lower()
        if "refund" in text_lower:
            cost_type = "blocked_refund_request"
        elif "discount" in text_lower or "promo" in text_lower:
            cost_type = "blocked_discount_request"
        elif "status" in text_lower or "check" in text_lower or "track" in text_lower:
            cost_type = "blocked_status_check"
        else:
            cost_type = "blocked_general_query"

        cost = COST_MODEL[cost_type]["cost_inr"]
        total_cost += cost

        fp_details.append({
            "id": fp["id"],
            "text": fp["text"],
            "cost_type": cost_type,
            "cost_inr": cost,
            "confidence": fp["confidence"],
            "reason": fp["reason"],
        })

    return {
        "total_false_positives": len(false_positives),
        "total_cost_inr": total_cost,
        "average_cost_per_fp": round(total_cost / len(false_positives), 2) if false_positives else 0,
        "cost_model": COST_MODEL,
        "false_positive_details": fp_details,
    }


def precision_recall_tradeoff(test_set, thresholds=None, use_llm=False):
    """Compute precision-recall at multiple confidence thresholds."""
    if thresholds is None:
        thresholds = [0.3, 0.5, 0.7, 0.9]

    tradeoff_table = []

    for threshold in thresholds:
        results = evaluate_at_threshold(
            test_set,
            block_threshold=threshold,
            flag_threshold=threshold * 0.5,
            use_llm=use_llm,
        )
        overall, per_category = compute_metrics(results)
        fp_cost = compute_fp_cost(results)

        tradeoff_table.append({
            "block_threshold": threshold,
            "flag_threshold": round(threshold * 0.5, 2),
            "precision": overall["precision"],
            "recall": overall["recall"],
            "f1": overall["f1"],
            "accuracy": overall["accuracy"],
            "tp": overall["tp"],
            "fp": overall["fp"],
            "fn": overall["fn"],
            "tn": overall["tn"],
            "fp_cost_inr": fp_cost["total_cost_inr"],
        })

    return tradeoff_table


def get_failure_cases(results):
    """Extract and categorize failure cases for honest reporting."""
    failures = {
        "false_positives": [],
        "false_negatives": [],
    }

    for r in results:
        if not r["is_malicious"] and r["predicted_malicious"]:
            failures["false_positives"].append({
                "id": r["id"],
                "category": r["category"],
                "text": r["text"],
                "confidence": r["confidence"],
                "reason": r["reason"],
            })
        elif r["is_malicious"] and not r["predicted_malicious"]:
            failures["false_negatives"].append({
                "id": r["id"],
                "category": r["category"],
                "text": r["text"],
                "confidence": r["confidence"],
                "reason": r["reason"],
            })

    return failures


def format_results_table(overall, per_category, tradeoff_table, fp_cost, failures):
    """Format results as a readable text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("PayGuard Evaluation Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("=" * 70)

    lines.append("\n## Overall Metrics (Heuristic-Only Mode)")
    lines.append(f"  Precision:  {overall['precision']:.4f}")
    lines.append(f"  Recall:     {overall['recall']:.4f}")
    lines.append(f"  F1 Score:   {overall['f1']:.4f}")
    lines.append(f"  Accuracy:   {overall['accuracy']:.4f}")
    lines.append(f"  TP: {overall['tp']}  FP: {overall['fp']}  FN: {overall['fn']}  TN: {overall['tn']}")

    lines.append("\n## Per-Category Metrics")
    lines.append(f"  {'Category':<22} {'Precision':>10} {'Recall':>10} {'F1':>10} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
    lines.append("  " + "-" * 75)
    for cat, m in sorted(per_category.items()):
        lines.append(f"  {cat:<22} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f} "
                      f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['tn']:>5}")

    lines.append("\n## Precision-Recall Tradeoff Table")
    lines.append(f"  {'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FP Cost (₹)':>12}")
    lines.append("  " + "-" * 55)
    for row in tradeoff_table:
        lines.append(f"  {row['block_threshold']:>10.2f} {row['precision']:>10.4f} "
                      f"{row['recall']:>10.4f} {row['f1']:>10.4f} {row['fp_cost_inr']:>12}")

    lines.append(f"\n## False Positive Cost Analysis")
    lines.append(f"  Total false positives: {fp_cost['total_false_positives']}")
    lines.append(f"  Total estimated cost: ₹{fp_cost['total_cost_inr']:,}")
    lines.append(f"  Average cost per FP: ₹{fp_cost['average_cost_per_fp']:,.2f}")

    lines.append("\n## Failure Cases (False Negatives — attacks that got through)")
    if failures["false_negatives"]:
        for fn in failures["false_negatives"]:
            lines.append(f"  ✗ [{fn['id']}] {fn['category']}: {fn['text']}")
            lines.append(f"    Confidence: {fn['confidence']:.2f} | Reason: {fn['reason']}")
    else:
        lines.append("  None — all attacks were caught!")

    lines.append("\n## Failure Cases (False Positives — legitimate requests blocked)")
    if failures["false_positives"]:
        for fp in failures["false_positives"]:
            lines.append(f"  ✗ [{fp['id']}] {fp['category']}: {fp['text']}")
            lines.append(f"    Confidence: {fp['confidence']:.2f} | Reason: {fp['reason']}")
    else:
        lines.append("  None — no legitimate requests were blocked!")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def run_evaluation(use_llm=False, verbose=True):
    """Run the full evaluation pipeline."""
    print("Loading test set...")
    test_set = load_test_set()
    print(f"Loaded {len(test_set)} test examples")

    # Seed test orders for action screening
    seed_test_orders()

    # Evaluate at default threshold
    print(f"\nRunning evaluation (LLM={'ON' if use_llm else 'OFF'})...")
    results = evaluate_at_threshold(test_set, use_llm=use_llm, verbose=verbose)
    overall, per_category = compute_metrics(results)

    # False positive cost
    fp_cost = compute_fp_cost(results)

    # Precision-recall tradeoff
    print("\nComputing precision-recall tradeoff...")
    tradeoff_table = precision_recall_tradeoff(test_set, use_llm=use_llm)

    # Failure cases
    failures = get_failure_cases(results)

    # Format report
    report = format_results_table(overall, per_category, tradeoff_table, fp_cost, failures)
    print("\n" + report)

    # Save results
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)

    results_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": {
            "use_llm": use_llm,
            "default_block_threshold": 0.7,
            "default_flag_threshold": 0.4,
        },
        "test_set_size": len(test_set),
        "overall_metrics": overall,
        "per_category_metrics": per_category,
        "tradeoff_table": tradeoff_table,
        "fp_cost_analysis": fp_cost,
        "failure_cases": failures,
        "detailed_results": results,
    }

    results_path = os.path.join(results_dir, "evaluation_results.json")
    with open(results_path, "w") as f:
        json.dump(results_data, f, indent=2, ensure_ascii=False)
    print(f"\nDetailed results saved to: {results_path}")

    report_path = os.path.join(results_dir, "evaluation_report.txt")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved to: {report_path}")

    return results_data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PayGuard Evaluation")
    parser.add_argument("--llm", action="store_true", help="Use LLM for screening (slower, more accurate)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-example output")
    args = parser.parse_args()

    run_evaluation(use_llm=args.llm, verbose=not args.quiet)
