// #define private public
#include "DataBuffer.h"

using namespace netflix::base;
// void foo(const char *)
// {

// }
int main(int argc, char **argv)
{
    shared_ptr<DataPool> pool(new DataPool);
    pool->init(1024);
    pool->dump();
    DataBuffer buf = pool->create(512);
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
