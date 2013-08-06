// #define private public
#include "DataBuffer.h"

using namespace netflix::base;
// void foo(const char *)
// {

// }
int main(int argc, char **argv)
{
    shared_ptr<DataPool> pool(new DataPool);
    pool->init(100);
    // pool->dump();
    DataBuffer buf1 = pool->create(50);
    DataBuffer buf2 = pool->create(50);
    buf2.clear();
    buf1.clear();
    DataBuffer buf3 = pool->create(60);
    DataBuffer buf4 = pool->create(10);
    buf3.clear();
    pool->defrag();

    // buf2.clear();
    // buf2 = pool->create(20);
    pool->dump();
    // // DataPointer<const char*> foo;
    // // ::foo(foo);

    // (void)argc;
    // (void)argv;
    // DataBuffer foo("balle");
    // foo += '1';
    // printf("foo %s\n", foo.c_str().data());
    return 0;
}
