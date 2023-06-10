#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Change the signature of fuzzme to match LLVMFuzzerTestOneInput
int LLVMFuzzerTestOneInput(const char *data, size_t size) {
    char buf[size + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    // Call the fuzzme function with the provided data
    fuzzme(buf);

    return 0;
}

int fuzzme(char *buf) {
    if (strlen(buf) >= 3)
        if (buf[0] == 'b')
            if (buf[1] == 'u')
                if (buf[2] == 'g') {
                    printf("You've got it!");
                    abort();
                }
    return 0;
}

