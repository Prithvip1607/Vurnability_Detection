from pipeline.risk import zero_day_score, risk_score, attack_techniques

def test_zero_day_candidate_without_cve():
    score, evidence = zero_day_score({"title": "0day remote code execution", "text": "actively exploited PoC"}, 3)
    assert score >= 60 and evidence

def test_cve_reduces_zero_day_confidence():
    score, _ = zero_day_score({"cve_ids": ["CVE-2026-1234"], "title": "RCE", "text": "exploit"}, 1)
    assert score < 60

def test_attack_mapping():
    found = attack_techniques({"title": "Remote Code Execution", "text": "privilege escalation"})
    ids = {x["id"] for x in found}
    assert "T1190" in ids and "T1068" in ids

def test_risk_score_bounds():
    score, _ = risk_score({"signal_score": 25, "nvd_data": [{"cvss_v3": {"score": 9.8}}], "epss": .9, "text": "actively exploited"}, 4)
    assert 0 <= score <= 100
