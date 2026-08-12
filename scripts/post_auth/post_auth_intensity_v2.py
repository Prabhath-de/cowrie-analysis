import math

P50 = 2
P75 = 8
P90 = 28
P95 = 55.75
P99 = 761
MAX = 13431

# Calibration points:
# command volume -> intensity score
POINTS = [
    (0, 0.0),
    (P50, 0.5),
    (P75, 1.0),
    (P90, 1.5),
    (P95, 2.5),
    (P99, 3.5),
    (MAX, 5.0),
]

def intensity_score(x):
    x = max(0, x)

    if x >= MAX:
        return 5.0

    for i in range(1, len(POINTS)):
        x0, y0 = POINTS[i - 1]
        x1, y1 = POINTS[i]

        if x <= x1:
            if x1 == x0:
                return y1

            if x0 == 0:
                # Linear from 0 to P50
                ratio = x / x1
            else:
                # Logarithmic interpolation
                ratio = (
                    math.log1p(x) - math.log1p(x0)
                ) / (
                    math.log1p(x1) - math.log1p(x0)
                )

            return y0 + ratio * (y1 - y0)

    return 5.0


print("=" * 60)
print("POST-AUTH INTENSITY V3")
print("=" * 60)

for x in [
    0, 1, 2, 5, 8, 10, 20, 28,
    50, 55.75, 100, 200, 500,
    700, 750, 760, 761, 762,
    800, 900, 1000, 1200, 1500,
    2000, 5000, 10000, 13431
]:
    print(f"{x:8.2f} -> {intensity_score(x):6.3f} / 5")
