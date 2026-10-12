from dataclasses import dataclass, field

DISCLAIMER = "plate coverage, not a security guarantee"
VALID_STATUS = ("intact", "scored", "broken", "unknown")
PLATE_NAMES = ("firewall", "ports", "ssh", "updates", "secrets")


@dataclass
class Plate:
    name: str
    status: str
    evidence: list[str] = field(default_factory=list)
    error: str | None = None
    headline: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUS:
            raise ValueError(f"invalid plate status: {self.status}")
        self.evidence = [str(line) for line in self.evidence]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "headline": self.headline,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "error": self.error,
        }


@dataclass
class Meter:
    score: int
    label: str
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "disclaimer": self.disclaimer,
        }


@dataclass
class Report:
    host: str
    plates: list[Plate]
    meter: Meter
    read_only: bool = True

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "read_only": self.read_only,
            "disclaimer": self.meter.disclaimer,
            "meter": self.meter.to_dict(),
            "plates": [plate.to_dict() for plate in self.plates],
        }


def unknown_plate(name: str, error: str, detail: str = "unreadable") -> Plate:
    return Plate(
        name=name,
        status="unknown",
        headline="unknown",
        detail=detail,
        evidence=[error],
        error=error,
    )
