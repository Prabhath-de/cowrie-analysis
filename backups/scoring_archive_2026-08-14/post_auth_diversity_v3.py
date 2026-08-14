import math

P95 = 3
P99 = 14
MAX = 17

POINTS = [
    (0, 0.0),
    (1, 0.0),
    (P95, 1.0),
    (P99, 2.0),
    (MAX, 3.0),
]

def diversity_score(x):
    x = max(0, x)

    if x <= 1:
        return 0.0

    if x >= MAX:
        return 3.0

    for i in range(1, len(POINTS)):
        x0, y0 = POINTS[i - 1]
        x1, y1 = POINTS[i]

        if x <= x1:
            ratio = (
                math.log1p(x) - math.log1p(x0)
            ) / (
                math.log1p(x1) - math.log1p(x0)
            )

            return y0 + ratio * (y1 - y0)

    return 3.0


print("=" * 60)
print("POST-AUTH DIVERSITY V3")
print("=" * 60)

for x in [
    0, 1, 2, 3, 4, 5, 8,
    10, 12, 13, 14, 15, 16, 17
]:
    print(f"{x:8.2f} -> {diversity_score(x):6.3f} / 3")
