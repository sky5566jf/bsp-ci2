// bs_test.m —— 对照组：完全空的 dylib
// 用途：区分"dylib 加载机制失败"与"constructor 代码崩溃"
//   若本 dylib 也导致 Agent 起不来 -> 是注入机制/签名/环境问题
//   若本 dylib OK -> 问题是原 constructor 里调 dyld API/ObjC
#include <stdio.h>

__attribute__((constructor))
static void bs_test_entry(void) {
    // 故意什么都不做，连 printf 都不要（避免任何副作用）
}
