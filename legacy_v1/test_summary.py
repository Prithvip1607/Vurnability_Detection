#!/usr/bin/env python3
"""
Test script for AI summary generation.
Run this to verify the summarizer is working correctly.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline.summarizer import generate_summary

# Test cases
test_items = [
    {
        "id": "test_1",
        "platform": "reddit",
        "source": "r/netsec",
        "title": "PAN-OS Zero-Day RCE actively exploited",
        "text": """A critical vulnerability in Palo Alto Networks PAN-OS allows unauthenticated 
        remote code execution through the captive portal feature. The vulnerability, tracked as 
        CVE-2025-0282, is being actively exploited in the wild by threat actors. Organizations 
        using PAN-OS should immediately apply the emergency patch released by Palo Alto Networks."""
    },
    {
        "id": "test_2",
        "platform": "github",
        "source": "github_repos",
        "title": "PoC exploit for Windows kernel privilege escalation",
        "text": """This repository contains a proof-of-concept exploit for a Windows kernel 
        vulnerability that allows local privilege escalation to SYSTEM. The vulnerability 
        affects Windows 10 and Windows 11 versions prior to the March 2025 security update."""
    },
    {
        "id": "test_3",
        "platform": "blog",
        "source": "BleepingComputer",
        "title": "New ransomware campaign targets healthcare sector",
        "text": """Security researchers have discovered a new ransomware campaign specifically 
        targeting healthcare organizations. The attackers are exploiting unpatched VPN 
        vulnerabilities to gain initial access."""
    }
]

def main():
    print("=" * 80)
    print("AI SUMMARY GENERATION TEST")
    print("=" * 80)
    print()
    
    # Check if OpenAI is configured
    if os.getenv("OPENAI_API_KEY"):
        print("✓ OpenAI API key found - will use AI generation")
    else:
        print("⚠ OpenAI API key not found - will use fallback extraction")
    print()
    
    for i, item in enumerate(test_items, 1):
        print(f"Test {i}/{len(test_items)}")
        print("-" * 80)
        print(f"Title: {item['title']}")
        print(f"Platform: {item['platform']}")
        print()
        
        try:
            summary = generate_summary(item)
            print(f"✓ Summary generated ({len(summary)} chars):")
            print(f"  {summary}")
            print()
        except Exception as e:
            print(f"✗ Error: {e}")
            print()
    
    print("=" * 80)
    print("Test complete!")
    print()
    print("Next steps:")
    print("1. If using fallback extraction, add OPENAI_API_KEY to .env for AI summaries")
    print("2. Run the full pipeline: python main.py --once")
    print("3. Check frontend: http://localhost:5173/vulns")

if __name__ == "__main__":
    main()
