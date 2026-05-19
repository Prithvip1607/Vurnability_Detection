"""
AI-powered vulnerability summarizer.

Generates concise, user-friendly summaries of vulnerability findings
using OpenAI API (or fallback to local extraction).
"""
import os
import re
from typing import Optional

from utils.logger import get_logger

logger = get_logger("summarizer")

# Try to import OpenAI
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI not installed. Install with: pip install openai")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def generate_summary(item: dict) -> str:
    """
    Generate a brief 2-3 sentence summary of the vulnerability.
    
    Returns:
        - AI-generated summary if OpenAI is available
        - Fallback extracted summary if not
    """
    title = item.get("title", "")
    text = item.get("text", "")[:1500]  # Limit to first 1500 chars
    platform = item.get("platform", "")
    source = item.get("source", "")
    
    # Try AI generation first
    if OPENAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
        try:
            summary = _generate_with_openai(title, text, platform, source)
            if summary:
                logger.debug("Generated AI summary for: %s", item.get("id"))
                return summary
        except Exception as e:
            logger.warning("OpenAI summary failed: %s", e)
    
    # Fallback to extraction
    return _extract_summary(title, text)


def _generate_with_openai(title: str, text: str, platform: str, source: str) -> Optional[str]:
    """Generate summary using OpenAI API."""
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    prompt = f"""You are a cybersecurity analyst. Generate a brief 2-3 sentence summary of this vulnerability finding.

Title: {title}
Source: {platform} - {source}
Content: {text}

Requirements:
- Be concise and technical
- Mention the affected product/vendor if identified
- Highlight the vulnerability type (RCE, auth bypass, etc.)
- Include CVE ID if present
- Use present tense
- Maximum 3 sentences

Summary:"""

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst who writes concise vulnerability summaries."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=150,
        temperature=0.3,
    )
    
    summary = response.choices[0].message.content.strip()
    return summary if summary else None


def _extract_summary(title: str, text: str) -> str:
    """Fallback: Extract first meaningful sentences from text."""
    # If text is short enough, use it directly
    if len(text) <= 200:
        return text.strip()
    
    # Try to extract first 2-3 sentences
    sentences = re.split(r'[.!?]\s+', text)
    summary_parts = []
    char_count = 0
    
    for sentence in sentences[:5]:  # Check first 5 sentences
        sentence = sentence.strip()
        if not sentence or len(sentence) < 20:
            continue
        
        summary_parts.append(sentence)
        char_count += len(sentence)
        
        if char_count >= 200 or len(summary_parts) >= 3:
            break
    
    if summary_parts:
        summary = ". ".join(summary_parts)
        if not summary.endswith("."):
            summary += "."
        return summary
    
    # Last resort: truncate text
    return text[:250].strip() + "..."


def batch_generate_summaries(items: list[dict]) -> dict[str, str]:
    """
    Generate summaries for multiple items.
    Returns dict mapping item_id -> summary.
    """
    summaries = {}
    for item in items:
        item_id = item.get("id")
        if not item_id:
            continue
        
        try:
            summary = generate_summary(item)
            summaries[item_id] = summary
        except Exception as e:
            logger.error("Summary generation failed for %s: %s", item_id, e)
            summaries[item_id] = _extract_summary(
                item.get("title", ""),
                item.get("text", "")
            )
    
    return summaries
