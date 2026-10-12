from shieldwall.model import DISCLAIMER, VALID_STATUS, Meter

POINTS = {
    "intact": 20,
    "scored": 10,
    "broken": 0,
    "unknown": 0,
}


def armor_meter(statuses: list[str]) -> Meter:
    for status in statuses:
        if status not in VALID_STATUS:
            raise ValueError(f"invalid plate status: {status}")
    score = min(100, sum(POINTS[status] for status in statuses))
    if any(status == "broken" for status in statuses):
        label = "blood"
    elif statuses and all(status == "intact" for status in statuses):
        label = "steel"
    else:
        label = "bone"
    return Meter(score=score, label=label, disclaimer=DISCLAIMER)


def meter_phrase(meter: Meter, statuses: list[str]) -> str:
    broken = sum(1 for status in statuses if status == "broken")
    if broken:
        noun = "plate" if broken == 1 else "plates"
        return f"{meter.label} / {broken} {noun} broken"
    if any(status != "intact" for status in statuses):
        return f"{meter.label} / coverage worn"
    return f"{meter.label} / plates intact"
