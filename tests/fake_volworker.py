"""Synthetic subprocess fixture, NEVER imported by production application code."""
import csv
import sys
import time
from pathlib import Path

args = sys.argv[1:]
plugin = next(x for x in args if x.startswith("test."))
output = Path(args[args.index("-o") + 1])
image = Path(args[args.index("-f") + 1])
if plugin == "test.stream.Plugin":
    log = Path(args[args.index("-l") + 1])
    writer = csv.writer(sys.stdout, lineterminator="\n", escapechar="\\")
    writer.writerow(["TreeDepth", "PID", "ImageFileName"])
    sys.stdout.flush()
    for i in range(3):
        print(f"\rProgress: {i*40:.2f} SYNTHETIC streaming operation\r", file=sys.stderr, end="", flush=True)
        with log.open("a") as stream: stream.write(f"SYNTHETIC engine detail {i}\n")
        writer.writerow([0, 4+i, "fixture.exe"]); sys.stdout.flush()
        time.sleep(.45)
    sys.exit(0)
if plugin == "test.slow.Plugin":
    print("Synthetic slow operation", file=sys.stderr, flush=True)
    time.sleep(60)
if plugin == "test.fail.Plugin":
    print("Unable to validate the plugin requirements: synthetic fixture", file=sys.stderr)
    sys.exit(1)
if plugin == "test.partial.Plugin":
    print('TreeDepth,PID\n0,123\n0,"unterminated', end="")
    sys.exit(0)
writer = csv.writer(sys.stdout, lineterminator="\n", escapechar="\\")
writer.writerow(["TreeDepth", "PID", "ImageFileName", "Path", "Comment"])
if plugin != "test.empty.Plugin":
    writer.writerow([0, 123, "synthetic.exe", r"C:\Program Files\Example\test.exe", "=1+1"])
    writer.writerow([1, 456, "example.exe", r"C:\User\sample.bin", "<script>alert('x')</script>\nsecond line"])
if plugin == "test.warn.Plugin":
    print("WARNING synthetic warning for test coverage", file=sys.stderr)
if plugin == "test.change.Plugin":
    with image.open("ab") as stream:
        stream.write(b"changed-by-synthetic-fixture")
(output / "synthetic-artifact.bin").write_bytes(b"not executable; synthetic test bytes")
print("Synthetic subprocess fixture completed", file=sys.stderr)
