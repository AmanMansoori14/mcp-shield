"""Record docs/assets/demo.gif from a *real* run of the demo (TS-C7).

    uv run python scripts/make_demo_gif.py            # fresh run: demo driver + shield stats
    uv run python scripts/make_demo_gif.py --from out.txt

Nothing is staged: the text in the GIF is the captured stdout of `demo.drive` and
`shield stats`, replayed line by line in a terminal-style frame.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "demo.gif"
W, H, PAD, LINE = 1180, 700, 22, 21
COLS = 112
BG, FG, DIM = (24, 26, 27), (226, 228, 224), (140, 144, 138)
GREEN, RED, AMBER, CYAN, TEAL = (
    (95, 200, 110),
    (240, 100, 95),
    (240, 190, 80),
    (110, 190, 230),
    (60, 190, 170),
)
FONT_CANDIDATES = ["/System/Library/Fonts/Menlo.ttc", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]


def capture() -> str:
    db = ROOT / "examples" / "shield-audit.db"
    for p in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
        p.unlink(missing_ok=True)
    run = lambda *cmd: subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout  # noqa: E731
    drive = run("uv", "run", "python", "-m", "demo.drive", "examples/shield.yaml")
    stats = run("uv", "run", "shield", "stats", "--config", "examples/shield.yaml", "--last", "6")
    return "$ make demo\n" + drive + "\n$ shield stats\n" + stats


def colour(line: str) -> tuple[int, int, int]:
    if line.startswith("$"):
        return TEAL
    if "→ ERROR" in line:
        return RED
    if "↳" in line:
        return CYAN
    if "→ ok" in line:
        return GREEN
    if re.search(r"\b(critical|high)\b", line) and "×" in line:
        return RED
    if re.search(r"\b(medium)\b", line) and "×" in line:
        return AMBER
    if line.startswith(("tools/list", "connected", "MCP Shield audit")) or "Security events" in line:
        return FG
    return DIM if line.startswith("   (") else FG


def font() -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for f in FONT_CANDIDATES:
        if Path(f).exists():
            return ImageFont.truetype(f, 15)
    return ImageFont.load_default()


def frame(lines: list[str], fnt: ImageFont.FreeTypeFont | ImageFont.ImageFont, cursor: bool) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, W - 1, 34), radius=10, fill=(40, 43, 44))
    for i, c in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        d.ellipse((16 + i * 22, 11, 28 + i * 22, 23), fill=c)
    d.text((W // 2 - 110, 9), "mcp-shield · real demo run", font=fnt, fill=DIM)
    visible = lines[-((H - 50) // LINE) :]
    y = 46
    for line in visible:
        d.text((PAD, y), line, font=fnt, fill=colour(line))
        y += LINE
    if cursor and visible:
        x = PAD + int(fnt.getlength(visible[-1])) + 2
        d.rectangle((x, y - LINE + 3, x + 8, y - 3), fill=FG)
    return img


def build(text: str) -> None:
    raw = [ln.rstrip() for ln in text.splitlines()]
    lines = [ln if len(ln) <= COLS else ln[: COLS - 1] + "…" for ln in raw if not ln.startswith('{"level"')]
    fnt = font()
    frames: list[Image.Image] = []
    durations: list[int] = []
    shown: list[str] = []
    for ln in lines:
        if ln.startswith("$ "):  # type the command
            for k in range(2, len(ln) + 1, 2):
                frames.append(frame([*shown, ln[:k]], fnt, cursor=True))
                durations.append(55)
            shown.append(ln)
            frames.append(frame(shown, fnt, cursor=False))
            durations.append(500)
            continue
        shown.append(ln)
        if not ln.strip():
            continue
        frames.append(frame(shown, fnt, cursor=False))
        durations.append(900 if ("→" in ln or "↳" in ln) else 160)
    durations[-1] = 4500
    # One shared palette for every frame, seeded with every text color (not just the last frame's).
    seed = frames[-1].copy()
    for i, c in enumerate([FG, DIM, GREEN, RED, AMBER, CYAN, TEAL]):
        seed.paste(c, (i * 40, H - 12, i * 40 + 40, H))
    palette = seed.convert("P", palette=Image.Palette.ADAPTIVE, colors=96)
    paletted = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    paletted[0].save(
        OUT, save_all=True, append_images=paletted[1:], duration=durations, loop=0, optimize=True
    )
    print(f"wrote {OUT} · {len(frames)} frames · {OUT.stat().st_size / 1024:.0f} KB")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--from", dest="src", type=Path, help="replay a saved capture instead of running the demo"
    )
    a = ap.parse_args()
    text = a.src.read_text() if a.src else capture()
    (OUT.parent / "demo-output.txt").write_text(text)
    build(text)


if __name__ == "__main__":
    main()
