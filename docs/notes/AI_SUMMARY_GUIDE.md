# AI-Generated Vulnerability Summaries

## Overview

The EVVP system now automatically generates concise, user-friendly summaries for every vulnerability finding. This allows users to quickly understand what each vulnerability is about without reading the full text.

## How It Works

### Pipeline Integration

Every collected vulnerability item goes through this enhanced pipeline:

```
1. Signal Scoring      → Filters noise
2. NVD Enrichment      → Adds CVSS data
3. AI Summary          → Generates 2-3 sentence summary ← NEW
4. Novelty Check       → Deduplicates
5. Storage             → Saves to database
6. CVE Tracking        → Monitors trends
7. Notification        → Alerts on critical items
```

### Summary Generation Methods

The system uses a **two-tier approach**:

#### 1. AI-Powered (Primary)
- Uses **OpenAI GPT-3.5-turbo** API
- Generates intelligent, context-aware summaries
- Mentions affected products, vulnerability types, CVE IDs
- Technical but concise (2-3 sentences max)
- Cost: ~$0.0001 per summary

#### 2. Fallback Extraction (Secondary)
- Activates when OpenAI API is unavailable or not configured
- Extracts first 2-3 meaningful sentences from text
- Truncates to ~200 characters
- No external dependencies
- Free

## Setup

### 1. Install Dependencies

```bash
cd evvp-backend
pip install -r requirements.txt
```

This installs:
- `openai>=1.0` - OpenAI Python SDK

### 2. Configure OpenAI API Key

Get your API key from: https://platform.openai.com/api-keys

Add to `.env`:

```env
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx
```

**Without API key:** System automatically falls back to text extraction (no errors).

### 3. Database Migration

The system automatically adds the `summary` column to `intel_raw` table on startup.

If using PostgreSQL, the schema update runs automatically:
```sql
ALTER TABLE intel_raw ADD COLUMN IF NOT EXISTS summary TEXT;
```

If using JSONL storage, summaries are stored in the JSON objects.

## Usage

### Backend

Summaries are generated automatically during collection. No manual intervention needed.

**Check logs:**
```bash
tail -f logs/pipeline.log | grep summary
```

**Example log output:**
```
2025-05-18 10:23:45 [DEBUG] summarizer: Generated AI summary for reddit_abc123: PAN-OS vulnerability allows unauthenticated remote code execution...
```

### Frontend

Summaries appear in the **All Vulnerability Findings** page:

**Before (without summary):**
```
[Score: 31] PAN-OS Zero-Day RCE actively exploited
[reddit] [CRITICAL] [CVE] [NEW]
```

**After (with summary):**
```
[Score: 31] PAN-OS Zero-Day RCE actively exploited
A critical vulnerability in Palo Alto Networks PAN-OS allows unauthenticated 
remote code execution through the captive portal feature. CVE-2025-0282 is 
being actively exploited in the wild.
[reddit] [CRITICAL] [CVE] [NEW]
```

### API Response

Summaries are included in all API responses:

```bash
curl http://localhost:8000/api/feed/all | jq '.items[0].summary'
```

**Response:**
```json
{
  "id": "reddit_abc123",
  "title": "PAN-OS Zero-Day RCE actively exploited",
  "summary": "A critical vulnerability in Palo Alto Networks PAN-OS allows unauthenticated remote code execution through the captive portal feature. CVE-2025-0282 is being actively exploited in the wild.",
  "signal_score": 31,
  "platform": "reddit",
  ...
}
```

## Customization

### Change AI Model

Edit `pipeline/summarizer.py`:

```python
response = client.chat.completions.create(
    model="gpt-4",  # Change to gpt-4 for better quality
    messages=[...],
    max_tokens=150,
    temperature=0.3,
)
```

**Model options:**
- `gpt-3.5-turbo` - Fast, cheap ($0.0005/1K tokens)
- `gpt-4` - Better quality ($0.03/1K tokens)
- `gpt-4-turbo` - Balanced ($0.01/1K tokens)

### Adjust Summary Length

Edit the prompt in `_generate_with_openai()`:

```python
prompt = f"""...
Requirements:
- Maximum 2 sentences  # Change from 3 to 2
...
"""
```

Or adjust `max_tokens`:
```python
max_tokens=100,  # Shorter summaries
```

### Disable AI Summaries

Remove or comment out the OpenAI API key in `.env`:

```env
# OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx
```

System will automatically use fallback extraction.

## Cost Estimation

### OpenAI API Costs

**GPT-3.5-turbo pricing:**
- Input: $0.0005 per 1K tokens
- Output: $0.0015 per 1K tokens

**Average per summary:**
- Input: ~300 tokens (title + text)
- Output: ~50 tokens (summary)
- Cost: ~$0.0001 per summary

**Monthly estimates:**
- 1,000 items/day = $3/month
- 10,000 items/day = $30/month
- 100,000 items/day = $300/month

### Free Tier

OpenAI provides $5 free credits for new accounts.
This covers ~50,000 summaries.

## Troubleshooting

### Summary field is empty

**Check 1:** OpenAI API key configured?
```bash
grep OPENAI_API_KEY .env
```

**Check 2:** OpenAI package installed?
```bash
pip show openai
```

**Check 3:** Check logs for errors:
```bash
grep -i "summary" logs/pipeline.log
```

### "OpenAI not installed" warning

Install the package:
```bash
pip install openai
```

### API rate limit errors

OpenAI free tier limits:
- 3 requests/minute
- 200 requests/day

**Solution:** Upgrade to paid tier or reduce collection frequency.

### Summaries are too long/short

Adjust `max_tokens` in `pipeline/summarizer.py`:
```python
max_tokens=100,  # Shorter
max_tokens=200,  # Longer
```

## Alternative AI Providers

### Use Anthropic Claude

Replace OpenAI with Anthropic:

```python
from anthropic import Anthropic

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
response = client.messages.create(
    model="claude-3-haiku-20240307",
    max_tokens=150,
    messages=[{"role": "user", "content": prompt}]
)
summary = response.content[0].text
```

### Use Local LLM (Ollama)

For free, offline summaries:

```python
import requests

response = requests.post("http://localhost:11434/api/generate", json={
    "model": "llama2",
    "prompt": prompt,
    "stream": False
})
summary = response.json()["response"]
```

## Performance Impact

**Summary generation adds:**
- ~200-500ms per item (with OpenAI API)
- ~10-50ms per item (with fallback extraction)

**Mitigation:**
- Summaries are generated asynchronously
- Does not block collection pipeline
- Failures fall back to extraction (no data loss)

## Future Enhancements

- [ ] Batch summary generation (reduce API calls)
- [ ] Cache summaries for duplicate items
- [ ] Multi-language support
- [ ] Severity-based summary detail level
- [ ] User-customizable summary templates
- [ ] Summary quality scoring

## Support

For issues or questions:
1. Check logs: `logs/pipeline.log`
2. Verify API key: `echo $OPENAI_API_KEY`
3. Test manually: `python -c "from pipeline.summarizer import generate_summary; print(generate_summary({'title': 'test', 'text': 'test'}))"
