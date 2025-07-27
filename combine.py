#!/usr/bin/env python3
"""
combine_sources.py  –  Merge every *.cpp and *.h file in the
current directory and all nested subdirectories into one text
file named output.txt.

For each source file, the script writes a banner
    // ===== <relative/path/to/filename> =====
followed by the file’s content, then a blank line.
"""

from pathlib import Path
from typing import List

OUTPUT_NAME = "output.txt"
BANNER_FMT  = "// ===== {name} =====\n"

def collect_sources(exts=(".cpp", ".h", "hpp")) -> List[Path]:
    """
    Return all source files in cwd and subdirectories with the given
    extensions, sorted by their relative path.
    """
    here = Path.cwd()
    files: List[Path] = []
    for ext in exts:
        files.extend(here.rglob(f"*{ext}"))
    # Exclude any file named exactly OUTPUT_NAME
    files = [p for p in files if p.is_file() and p.name != OUTPUT_NAME]
    # Sort by case-insensitive relative path
    return sorted(files, key=lambda p: str(p.relative_to(here)).lower())

def main() -> None:
    sources = collect_sources()
    if not sources:
        print("No .cpp or .h files found.")
        return

    with open(OUTPUT_NAME, "w", encoding="utf-8", newline="\n") as out:
        for src in sources:
            rel_path = src.relative_to(Path.cwd())
            out.write(BANNER_FMT.format(name=rel_path))
            out.write(src.read_text(encoding="utf-8"))
            out.write("\n\n")  # blank line between files

    print(f"Combined {len(sources)} files into {OUTPUT_NAME}")

if __name__ == "__main__":
    main()
