"""Static guard for the Windows entry points. Run by ``make verify`` and CI.

CI runs on Linux, so a ``.cmd`` file is never executed there -- which is exactly how a
``cmd.exe``-only defect shipped: ``start.cmd`` enabled delayed expansion and then assigned
``ST_BOOTSTRAP_ADMIN_PASSWORD=...9!``. ``cmd.exe`` consumed the ``!``, the API hashed a
22-character password, and the documented credential could never work.

These checks are deliberately blunt, because the failure mode is silent:

1. no ``EnableDelayedExpansion`` in any ``.cmd`` (nothing in this project needs it) -- with it
   off, the ``!`` in the bootstrap password below is an ordinary character;
2. no ``!`` inside a ``set "NAME=value"`` assignment in a file that turns delayed expansion
   on (in a file that does not, ``!`` is an ordinary character and is safe);
3. no ``!VAR!`` capture at all (use ``if errorlevel 1`` instead);
4. the bootstrap password literal in ``start.cmd`` matches ``start.sh`` and ``README.md``,
   so the credential an operator reads is the credential the API hashes;
5. the credential is only echoed behind the "first run" branch (never on every start);
6. no ``for /f`` whose command begins with a quote -- ``cmd.exe`` strips the outer quotes and
   tries to execute ``C:/path/python.exe" -c "import`` as a program name, which is the
   "'...' is not recognized" error shipped in start.cmd;
7. any ``--since %VAR%`` is preceded by ``if not defined VAR``, so an empty value cannot turn
   into ``--since --timeout 60`` and die with "--since: expected one argument".

Exit code 0 when every rule holds; 1 with one line per violation.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASSWORD_NAME = "ST_BOOTSTRAP_ADMIN_PASSWORD"
#: The documented length of the credential. A short value means a character was consumed.
EXPECTED_PASSWORD_LENGTH = 23

ASSIGN_RE = re.compile(r'^\s*set\s+"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^"]*)"\s*$')
CMD_RE = re.compile(r"^set\s+")
#: `for /f ... in ('"...'` -- a quoted command inside for /f is mangled by cmd.exe.
FOR_QUOTED_CMD_RE = re.compile(r"^\s*for\s+/f\b[^\r\n]*?\bin\s*\(\s*[`']\"")
#: `--since %VAR%` -- the value must be known to be set before it is interpolated.
SINCE_RE = re.compile(r"--since\s+%([A-Za-z_][A-Za-z0-9_]*)%")


def _cmd_files() -> list[Path]:
    return sorted(ROOT.glob("*.cmd"))


def _literal(text: str, name: str) -> str:
    for line in text.splitlines():
        match = ASSIGN_RE.match(line)
        if match and match.group("name") == name:
            return match.group("value")
    return ""


def check() -> list[str]:
    problems: list[str] = []
    for path in _cmd_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        # Only *active* lines count: the comment in start.cmd explains the defect by name and
        # must not be mistaken for the defect itself.
        active = [line for line in text.splitlines() if not line.strip().lower().startswith("rem")]
        delayed = any("enabledelayedexpansion" in line.lower() for line in active)
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.lower().startswith("rem"):
                continue
            if "enabledelayedexpansion" in stripped.lower():
                problems.append(
                    f"{path.name}:{number}: EnableDelayedExpansion consumes '!' inside a "
                    f"set \"...\" assignment -- use `if errorlevel 1` instead"
                )
            if "!VAR!" in stripped or re.search(r"(?<![!\"])![A-Za-z_][A-Za-z0-9_]*!(?![!\"])", stripped):
                problems.append(f"{path.name}:{number}: delayed-expansion capture '!VAR!' is not used here")
            if CMD_RE.match(stripped) and delayed:
                # Only a problem in a file that turned the mode on; `!` is inert otherwise.
                match = ASSIGN_RE.match(line)
                if match and "!" in match.group("value"):
                    problems.append(
                        f"{path.name}:{number}: '!' inside set \"{match.group('name')}=...\" while "
                        f"delayed expansion is enabled -- cmd.exe consumes it"
                    )
            if FOR_QUOTED_CMD_RE.match(stripped):
                problems.append(
                    f"{path.name}:{number}: `for /f` whose command starts with a quote is mangled by "
                    f"cmd.exe -- write the value to a file and use `set /p`, or drop the quotes"
                )

        # `--since %VAR%` needs a guard, or an empty VAR eats the next argument.
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            if line.strip().lower().startswith("rem"):
                continue
            match = SINCE_RE.search(line)
            if not match:
                continue
            name = match.group(1)
            guarded = any(
                re.search(rf"if\s+not\s+defined\s+{re.escape(name)}\b", earlier, re.IGNORECASE)
                for earlier in lines[: number - 1]
                if not earlier.strip().lower().startswith("rem")
            )
            if not guarded:
                problems.append(
                    f"{path.name}:{number}: `--since %{name}%` has no `if not defined {name}` guard -- "
                    f"an empty value fails with '--since: expected one argument'"
                )

    start_cmd = _literal((ROOT / "start.cmd").read_text(encoding="utf-8", errors="replace"), PASSWORD_NAME)
    start_sh = ""
    sh_path = ROOT / "start.sh"
    if sh_path.is_file():
        match = re.search(rf"export {PASSWORD_NAME}=['\"](?P<value>[^'\"]*)['\"]", sh_path.read_text(encoding="utf-8"))
        start_sh = match.group("value") if match else ""

    readme = ROOT / "README.md"
    readme_password = ""
    if readme.is_file():
        match = re.search(r"`(Bootstrap-[^`]+)`", readme.read_text(encoding="utf-8"))
        readme_password = match.group(1) if match else ""

    if not start_cmd:
        problems.append(f"start.cmd: {PASSWORD_NAME} is not set")
    elif len(start_cmd) != EXPECTED_PASSWORD_LENGTH:
        problems.append(
            f"start.cmd: {PASSWORD_NAME} is {len(start_cmd)} characters, expected "
            f"{EXPECTED_PASSWORD_LENGTH} -- a character was consumed"
        )
    for label, other in (("start.sh", start_sh), ("README.md", readme_password)):
        if other and start_cmd and other != start_cmd:
            problems.append(f"{label}: documented password differs from start.cmd's literal")

    start_text = (ROOT / "start.cmd").read_text(encoding="utf-8", errors="replace")
    branch_marker = 'if "%ST_USERS%"=="0" ('
    echo_token = f"%{PASSWORD_NAME}%"
    if echo_token in start_text:
        if branch_marker not in start_text:
            problems.append("start.cmd: the bootstrap password is echoed but there is no first-run branch")
        else:
            before_branch, rest = start_text.split(branch_marker, 1)
            block, _after = rest.split(") else (", 1) if ") else (" in rest else (rest, "")
            if echo_token not in block:
                problems.append(
                    "start.cmd: the bootstrap password is echoed outside the first-run branch -- "
                    "after bootstrap is skipped it is not a valid credential"
                )
            if echo_token in before_branch:
                problems.append("start.cmd: the bootstrap password is echoed before the first-run branch")
    return problems


def main() -> int:
    problems = check()
    if problems:
        for problem in problems:
            print(f"[fail] {problem}")
        print(f"\n{len(problems)} problem(s) in the Windows entry points")
        return 1
    print("windows scripts: delayed expansion off, no '!' in an assignment, no quoted for/f "
          "command, --since guarded, credentials consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
