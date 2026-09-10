from scanner.models import Finding
from scanner.triage import manual_review_queue, triage_lines


def _f(sev, title="t"):
    return Finding("WC-X", sev, title, "a.php", 1, "m", "A01", 0.9)


def test_queue_only_high():
    fs = [_f("HIGH"), _f("LOW"), _f("MEDIUM")]
    q = manual_review_queue(fs)
    assert len(q) == 1 and q[0].severity == "HIGH"


def test_triage_text():
    lines = triage_lines([_f("HIGH", "open ajax")])
    assert any("Manual review" in x for x in lines)
    assert any("open ajax" in x for x in lines)
