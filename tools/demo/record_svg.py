"""Records a real run of lab/local-demo.sh and writes it as an animated SVG for the README.

Every line shown is what the script printed, at the time it printed it; pauses longer than
MAX_GAP seconds (the build, servers starting) are shortened to MAX_GAP. Standard library
only. Run from the repository root:
  python3 -I tools/demo/record_svg.py docs/demo.svg
"""

import html
import subprocess
import sys
import time

COMMAND = "lab/local-demo.sh"
MAX_GAP = 0.9          # seconds: longer pauses are shortened to this
TYPE_TIME = 1.2        # seconds to "type" the command
END_PAUSE = 6.0        # seconds the final screen stays before the loop restarts
COLS, LINE_H, CHAR_W, PAD = 74, 21, 8.4, 18
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


def record():
    """(seconds since start, line) for every line the demo prints."""
    started = time.monotonic()
    proc = subprocess.Popen(
        ["bash", COMMAND], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    lines = []
    for line in proc.stdout:
        lines.append((time.monotonic() - started, line.rstrip("\n")))
    if proc.wait() != 0:
        sys.exit("the demo failed; nothing written")
    return lines


def compress(lines):
    """Shortens long pauses and starts the output after the typed command."""
    out, clock, previous = [], TYPE_TIME + 0.4, None
    for t, line in lines:
        gap = 0.25 if previous is None else min(t - previous, MAX_GAP)
        clock += max(gap, 0.05)
        previous = t
        out.append((clock, line))
    return out


def style(line):
    if line.startswith("ok "):
        return "ok"
    if line.startswith("LEAK"):
        return "leak"
    if line.startswith("=="):
        return "head"
    if line.startswith("--"):
        return "dim"
    return "plain"


def svg(timed):
    rows = len(timed) + 2
    width = int(COLS * CHAR_W + 2 * PAD)
    height = int(rows * LINE_H + 2 * PAD + 28)
    total = timed[-1][0] + END_PAUSE
    pct = lambda t: f"{100 * t / total:.3f}%"

    css = [
        f"text{{font-family:{FONT};font-size:14px;white-space:pre}}",
        ".plain{fill:#d0d7de}.ok{fill:#3fb950}.leak{fill:#f85149}",
        ".head{fill:#e6edf3;font-weight:600}.dim{fill:#8b949e}.prompt{fill:#79c0ff}",
    ]
    body = []
    y0 = PAD + 28 + LINE_H

    # The prompt and the command, revealed by a clip that grows in steps (typing).
    command_w = len(COMMAND) * CHAR_W
    css.append(
        f"@keyframes type{{0%{{width:0}}{pct(0.3)}{{width:0}}"
        f"{pct(0.3 + TYPE_TIME)},100%{{width:{command_w:.1f}px}}}}"
        f"#typing{{animation:type {total:.2f}s steps({len(COMMAND)},end) infinite}}"
    )
    body.append(f'<text x="{PAD}" y="{y0}" class="prompt">$</text>')
    body.append(
        f'<clipPath id="cmd"><rect id="typing" x="{PAD + 2 * CHAR_W}" y="{y0 - 15}" '
        f'height="{LINE_H}" width="0"/></clipPath>'
    )
    body.append(
        f'<text x="{PAD + 2 * CHAR_W}" y="{y0}" class="plain" clip-path="url(#cmd)">'
        f"{html.escape(COMMAND)}</text>"
    )

    for i, (t, line) in enumerate(timed):
        name = f"l{i}"
        css.append(
            f"@keyframes {name}{{0%,{pct(t)}{{opacity:0}}"
            f"{pct(t + 0.01)},100%{{opacity:1}}}}"
            f".{name}{{opacity:0;animation:{name} {total:.2f}s step-end infinite}}"
        )
        y = y0 + (i + 1) * LINE_H
        body.append(
            f'<text x="{PAD}" y="{y}" class="{style(line)} {name}">{html.escape(line)}</text>'
        )

    frame = (
        f'<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>'
        f'<circle cx="{PAD + 6}" cy="{PAD + 4}" r="6" fill="#ff5f57"/>'
        f'<circle cx="{PAD + 26}" cy="{PAD + 4}" r="6" fill="#febc2e"/>'
        f'<circle cx="{PAD + 46}" cy="{PAD + 4}" r="6" fill="#28c840"/>'
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="lab/local-demo.sh: the same attack through Resguardo and straight '
        f'to the provider">'
        f'<style>{"".join(css)}</style>{frame}{"".join(body)}</svg>\n'
    )


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/demo.svg"
    lines = record()
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg(compress(lines)))
    print(f"{out}: {len(lines)} lines recorded", file=sys.stderr)


main()
