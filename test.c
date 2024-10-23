/* compile with protomalloc */
#include <stdio.h>
#include "protomalloc.h"

int main() {
    malloc_options = "V";
    printf("Hello World!\n");
    return 0;
}
