/* P16 real-run fixture: a tiny ARM64 C harness.
 *
 * This is the behavioral (E5) end of the evidence chain: a function whose
 * change we want to PROVE BEHAVES is tested by a plain C main() that runs
 * assertions and prints a "N passed, M failed" summary — the exact shape
 * vibebot.harness.parse_harness expects.
 *
 * Built at test time by the P16 real-e2e block (cross gcc + qemu-aarch64),
 * NOT hand-rolled here. The function under test (popcount) is the same idiom
 * P15's classifier recognizes statically — so this fixture closes the loop
 * P15 (static, E3) -> P16 (runtime, E5) on a real build.
 */

#include <stdio.h>

/* Kernighan popcount: count the set bits in n by clearing the lowest one
 * each iteration. The "function under test". */
static int popcount(unsigned int n)
{
    int c = 0;
    while (n) {
        n &= n - 1u;
        c++;
    }
    return c;
}

static int g_pass = 0;
static int g_fail = 0;

static void expect(const char *name, int got, int want)
{
    if (got == want) {
        g_pass++;
        printf("PASS: %s\n", name);
    } else {
        g_fail++;
        printf("FAIL: %s (got %d, want %d)\n", name, got, want);
    }
}

int main(void)
{
    expect("popcount(0)", popcount(0u), 0);
    expect("popcount(1)", popcount(1u), 1);
    expect("popcount(0xff)", popcount(0xffu), 8);
    expect("popcount(0x80000000)", popcount(0x80000000u), 1);
    expect("popcount(0x55555555)", popcount(0x55555555u), 16);
    expect("popcount(0xffffffff)", popcount(0xffffffffu), 32);
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
