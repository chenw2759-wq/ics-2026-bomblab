#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count =1;
    (void)challenge;
    uint32_t H = (uint32_t)(challenge >> 32);
    uint32_t L = (uint32_t)challenge;
    uint32_t M = (uint32_t)(challenge >> 16);

    uint32_t s1 = ((H + 8u * M) ^ 0x5DA7u);
    uint32_t s0 = ((H + 0xD6DAu) ^ L);

    values[0] = (5u * s0) ^ (s1 + 0x4BE7u);
    return write_answer(out, cap, values, count);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 6;

    // 第一个字段：challenge 的 [43:36] 位，异或 2。
    values[0] = ((uint32_t)(challenge >> 36) & 0xffu) ^ 2u;

    // 后续字段是递推关系；rdx 同时作为循环下标参与减法。
    for (size_t i = 1; i < count; ++i) {
        uint32_t shift = (uint32_t)(10 + 2 * (i - 1));
        uint32_t nibble = (uint32_t)((challenge >> shift) & 0xfu);
        values[i] = (nibble + 5u) ^ (3u * values[i - 1] - (uint32_t)i);
    }

    return write_answer(out, cap, values, count);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t result = 0;

    // 汇编中先由 challenge 低 3 位选择分支。
    uint32_t selector = (uint32_t)challenge & 0x7u;

    // p3_dispatch 的第二个参数：
    // (uint32_t)(challenge >> 3) XOR (uint32_t)(challenge >> 32)。
    uint32_t x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);

    values[0] = selector;

    // 跳转表 0x405820 的映射不是顺序对应：
    // selector: 0  1  2  3  4  5  6  7
    // case:     0  7  5  2  1  4  6  3
    switch (selector) {
        case 0:  // p3_case_0
            result = 3u * x + 0x20f4u;
            break;
        case 1:  // p3_case_7
            result = (4u * x) ^ 0x5a60u;
            break;
        case 2:  // p3_case_5
            result = 5u * x + 0xa648u;
            break;
        case 3:  // p3_case_2
            result = (x ^ 0xa447u) + (x >> 1);
            break;
        case 4:  // p3_case_1
            result = (4u * x) ^ 0xa1cdu;
            break;
        case 5:  // p3_case_4
            result = 5u * x + 0x15aeu;
            break;
        case 6:  // p3_case_6
            result = (x ^ 0x4aacu) + (x >> 1);
            break;
        case 7:  // p3_case_3
            result = 5u * x + 0x3354u;
            break;
        default:
            return 1;
    }

    values[1] = result;
    return write_answer(out, cap, values, count);
}

static uint32_t p4_walk(uint32_t target, uint32_t lo, uint32_t hi, uint32_t key) {
    uint32_t mid = lo + ((hi - lo) >> 1u);

    if (target == mid) {
        return (mid + 0x29u) ^ key;
    }

    uint32_t mixed = mid + key;
    if (target > mid) {
        uint32_t child = p4_walk(target, mid + 1u, hi, key);
        return (3u * child) ^ mixed ^ 0x1au;
    }

    uint32_t child = p4_walk(target, lo, mid - 1u, key);
    return (3u * child) ^ mixed ^ 0x01u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;

    uint32_t target = (uint32_t)challenge & 0x7fu;
    uint32_t key = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);

    values[0] = p4_walk(target, 0, 0x7fu, key);
    return write_answer(out, cap, values, count);
}

struct p5_node {
    uint32_t next;
    uint32_t value;
    uint32_t tag;
};

/* p5_nodes 中每个节点对应 bomb 里 16 字节的节点；UINT32_MAX 表示 next == NULL。 */
static const struct p5_node p5_nodes[] = {
    {4,           338,  33455}, /* 0x405ba0 */
    {UINT32_MAX,  521,  54800}, /* 0x405bb0 */
    {1,           2870, 39169}, /* 0x405bc0 */
    {10,          2157, 59279}, /* 0x405bd0 */
    {7,           2353, 15020}, /* 0x405be0 */
    {8,           1038, 38146}, /* 0x405bf0 */
    {0,           1819, 53385}, /* 0x405c00 */
    {11,          1560, 37953}, /* 0x405c10 */
    {3,           2620, 37152}, /* 0x405c20 */
    {2,           881,  48049}, /* 0x405c30 */
    {9,           66,   5272},  /* 0x405c40 */
    {5,           1339, 59845}, /* 0x405c50 */
};

static const uint32_t p5_heads[8] = {6, 0, 4, 7, 11, 5, 8, 3};

static uint32_t p5_traverse(uint64_t challenge, uint32_t *last_out) {
    const struct p5_node *node = &p5_nodes[p5_heads[challenge & 7u]];

    uint32_t last = node->value;
    uint32_t acc = (uint32_t)(challenge >> 6)
                 ^ (uint32_t)(challenge >> 32)
                 ^ node->tag
                 ^ 0x5d71u;

    acc += last;

    uint32_t steps = ((uint32_t)challenge >> 3u) & 3u;
    for (uint32_t i = 0; i < steps; ++i) {
        node = &p5_nodes[node->next];
        last = node->value;
        acc ^= node->tag;
        acc += last;
    }

    *last_out = last;
    return acc;
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t last = 0;

    values[0] = p5_traverse(challenge, &last);
    values[1] = last;
    return write_answer(out, cap, values, count);
}

static uint32_t p6_op_0(uint32_t x) {
    return (2u * x + 0x845eu) ^ (7u * x);
}

static uint32_t p6_op_1(uint32_t x) {
    return ((x >> 3u) ^ x) + 0xae7au;
}

static uint32_t p6_op_2(uint32_t x) {
    return (x >> 7u) | (x << 25u);
}

static uint32_t p6_op_3(uint32_t x) {
    return (x + 0x476fu) ^ (x >> 5u);
}

static uint32_t p6_op_4(uint32_t x) {
    return ((x << 5u) | (x >> 27u)) ^ 0x7faeu;
}

static uint32_t p6_op_5(uint32_t x) {
    return (x ^ 0xcd7fu) + 8u * x;
}

static uint32_t p6_apply(unsigned int op, uint32_t x) {
    switch (op) {
        case 0: return p6_op_0(x);
        case 1: return p6_op_1(x);
        case 2: return p6_op_2(x);
        case 3: return p6_op_3(x);
        case 4: return p6_op_4(x);
        case 5: return p6_op_5(x);
        default: return 0;
    }
}

static const uint8_t p6_table[8] = {0, 3, 5, 2, 4, 4, 5, 1};

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;

    uint32_t idx1 = (uint32_t)challenge & 7u;
    uint32_t idx2 = ((uint32_t)challenge >> 3u) & 7u;
    uint32_t arg1 = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);

    uint32_t r1 = p6_apply(p6_table[idx1], arg1);
    uint32_t r2 = p6_apply(p6_table[idx2], r1 ^ 0x2096u);

    values[0] = r2 + 0x6b21u;
    return write_answer(out, cap, values, count);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t a = (uint32_t)context & 3u;

    uint32_t x = (uint32_t)(challenge >> 32) ^ (uint32_t)challenge;
    uint32_t y = (uint32_t)(context >> 32) ^ (uint32_t)context;

    uint32_t mix_in = x ^ y;

    /* secret_mix: ((v >> 1) ^ 0xc168) + (v ^ 0xe53) */
    uint32_t mix = ((mix_in >> 1) ^ 0xc168u) + (mix_in ^ 0xe53u);

    uint32_t r9 = (a * 0xe53u) ^ (uint32_t)(context >> 16);

    uint32_t b = mix ^ r9;
    uint32_t c = b ^ (y + a + 0xc168u + (x >> 1));

    /* secret_gate 在输入的第 32 字节处检查 "OPEN"，从第 36 字节开始解析三个整数。 */
    static const char prefix[] = "00000000000000000000000000000000";
    int n = snprintf(out, cap, "%sOPEN %" PRIu32 " %" PRIu32 " %" PRIu32,
                     prefix, a, b, c);
    if (n < 0 || (size_t)n >= cap) return 1;

    return 0;
}
