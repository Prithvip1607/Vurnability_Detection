#!/usr/bin/env python3
"""
Cyber Threat Intelligence Collection System
Usage:
    python main.py                  # run all collectors
    python main.py --collector reddit
    python main.py --collector github
    python main.py --collector blog
    python main.py --once           # single pass (all collectors)
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from utils.logger import get_logger

logger = get_logger("main")


def main():
    parser = argparse.ArgumentParser(description="Cyber Threat Intel Collector")
    parser.add_argument("--collector", choices=["reddit", "github", "blog"], default=None)
    parser.add_argument("--once", action="store_true", help="Run a single collection pass then exit")
    parser.add_argument("--zeroday", action="store_true", help="Hunt for zero-day candidates from collected data")
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days for zero-day hunt (default: 7)")
    parser.add_argument("--minscore", type=int, default=10, help="Minimum zero-day score threshold (default: 10)")
    parser.add_argument("--limit", type=int, default=50, help="Max zero-day results to show (default: 50)")
    args = parser.parse_args()

    if args.zeroday:
        from utils.zero_day_hunter import hunt_zero_days, hunt_cve_vulns, print_zero_days, print_cve_vulns, export_results
        logger.info("Hunting vulnerabilities (last %d days, min score %d)", args.days, args.minscore)
        
        # Zero-day candidates (no CVE)
        zd = hunt_zero_days(days=args.days, min_score=args.minscore, limit=args.limit)
        print_zero_days(zd)
        if zd:
            export_results(zd, "zero_day_candidates.json")
        
        # CVE-tagged vulnerabilities
        cve = hunt_cve_vulns(days=args.days, min_score=args.minscore, limit=args.limit)
        print_cve_vulns(cve)
        if cve:
            export_results(cve, "cve_vulnerabilities.json")
        return

    from collectors import reddit_collector, github_collector, blog_collector

    collector_map = {
        "reddit": (reddit_collector.run_once, reddit_collector.run_continuous),
        "github": (github_collector.run_once, github_collector.run_continuous),
        "blog":   (blog_collector.run_once,   blog_collector.run_continuous),
    }

    if args.collector:
        run_once, run_continuous = collector_map[args.collector]
        logger.info("Starting single collector: %s (once=%s)", args.collector, args.once)
        run_once() if args.once else run_continuous()
    elif args.once:
        logger.info("Running single pass — all collectors")
        for name, (run_once, _) in collector_map.items():
            logger.info("Running %s once", name)
            try:
                run_once()
            except Exception as e:
                logger.error("%s failed: %s", name, e)
    else:
        logger.info("Starting all collectors")
        from scheduler.runner import start
        start()


if __name__ == "__main__":
    main()
