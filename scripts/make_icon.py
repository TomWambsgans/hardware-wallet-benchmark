"""Draw the app's 14x14 1-bit icon (a small Merkle tree) to ledger-app/icons/.

Run inside the app-builder image (it has Pillow):
    docker run --rm -v "$PWD:/w" -w /w ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
        python3 scripts/make_icon.py
"""

from PIL import Image

ART = """
..............
......##......
......##......
.....#..#.....
....#....#....
...#......#...
..##......##..
..##......##..
.#..#....#..#.
#....#..#....#
##..##..##..##
##..##..##..##
..............
..............
"""

rows = [r for r in ART.strip("\n").split("\n")]
assert len(rows) == 14 and all(len(r) == 14 for r in rows)
im = Image.new("P", (14, 14), 0)
im.putpalette([0, 0, 0, 255, 255, 255])
for y, row in enumerate(rows):
    for x, c in enumerate(row):
        im.putpixel((x, y), 1 if c == "#" else 0)
im.save("ledger-app/icons/pqbench_14px.gif")
print("wrote ledger-app/icons/pqbench_14px.gif")
