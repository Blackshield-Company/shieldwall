from shieldwall.runner import CommandResult


class FakeRunner:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}
        self.calls = []

    def run(self, argv, timeout=None):
        key = tuple(argv)
        self.calls.append(key)
        if key not in self.mapping:
            return CommandResult(key, None, "", "", not_found=True)
        return self.mapping[key]


def canned(argv, stdout="", stderr="", returncode=0, timed_out=False, not_found=False):
    return CommandResult(
        tuple(argv),
        returncode,
        stdout,
        stderr,
        timed_out=timed_out,
        not_found=not_found,
    )


def missing_log(_path):
    raise FileNotFoundError(_path)
