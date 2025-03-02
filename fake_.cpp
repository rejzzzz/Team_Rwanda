/*
 * CPU and Memory Stress Test
 * WARNING: This program will consume system resources.
 * Use responsibly and only for testing purposes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    unsigned long long counter = 0;
    int *ptr_array[1000];
    int i = 0;

    printf("Starting resource consumption test...\n");

    while (1)
    { // Infinite loop
        // Allocate memory (1MB each iteration)
        ptr_array[i % 1000] = (int *)malloc(1024 * 1024);

        if (ptr_array[i % 1000] != NULL)
        {
            // Write to memory to ensure it's allocated
            memset(ptr_array[i % 1000], 1, 1024 * 1024);

            // CPU-intensive calculation
            for (int j = 0; j < 10000000; j++)
            {
                counter += j;
            }

            if (i % 10 == 0)
            {
                printf("Iteration: %d, Memory allocated: %d MB\n", i, i % 1000 + 1);
            }
            i++;
        }
        else
        {
            printf("Memory allocation failed at iteration %d\n", i);
        }
    }

    return 0; // Never reaches here
}