import math

P50 = 2
P75 = 8
P90 = 28
P95 = 55.75
P99 = 761
MAX = 13431

def intensity_score(x):

    if x <= P50:
        return 0.5 * (x / P50)

    elif x <= P75:
        return 0.5 + 1.0 * (
            math.log1p(x/P50) /
            math.log1p(P75/P50)
        ) - 0.5

    elif x <= P90:
        return 1.5 + 1.0 * (
            math.log1p(x/P75) /
            math.log1p(P90/P75)
        ) - 1.0

    elif x <= P95:
        return 2.5 + 1.0 * (
            math.log1p(x/P90) /
            math.log1p(P95/P90)
        ) - 1.0

    elif x <= P99:
        return 3.5 + 1.0 * (
            math.log1p(x/P95) /
            math.log1p(P99/P95)
        ) - 1.0

    else:
        # Saturate gradually from P99 to MAX
        if MAX <= P99:
            return 5.0

        return 4.0 + (
            math.log1p(x/P99) /
            math.log1p(MAX/P99)
        )


print("=" * 60)
print("POST-AUTH INTENSITY V2")
print("=" * 60)

for x in [0,1,2,5,8,10,20,28,50,55.75,100,200,500,761,1000,5000,13431]:
    print(f"{x:8.2f} -> {intensity_score(x):6.3f} / 5")
