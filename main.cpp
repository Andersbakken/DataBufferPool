// #define private public
#include "DataBuffer.h"

using namespace netflix::base;
// void foo(const char *)
// {

// }
int main(int argc, char **argv)
{
    // DataPointer<const char*> foo;
    // ::foo(foo);

    (void)argc;
    (void)argv;
    DataBuffer foo("balle");
    foo += '1';
    printf("foo %s\n", foo.c_str().data());
    return 0;
}
