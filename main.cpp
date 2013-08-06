#include "DataBuffer.h"

using namespace netflix::base;
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    DataBuffer foo("balle");
    foo += '1';
    printf("foo %s\n", foo.c_str());
    return 0;
}
