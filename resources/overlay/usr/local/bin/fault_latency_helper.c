// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Helper program for measuring anonymous memory fault-in latency.
// Allocates memory using mmap with MAP_ANONYMOUS | MAP_PRIVATE, then
// touches the first byte in each page using either sequential or random access.
// Measures the time taken to fault in all pages.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096

void shuffle_array(int *array, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <size_mb> <access_pattern>\n", argv[0]);
        printf("  size_mb: Size in MB to allocate\n");
        printf("  access_pattern: 'sequential' or 'random'\n");
        return 1;
    }

    int size_mb = atoi(argv[1]);
    char *access_pattern = argv[2];
    
    if (size_mb <= 0) {
        printf("Error: size_mb must be positive\n");
        return 1;
    }

    if (strcmp(access_pattern, "sequential") != 0 && strcmp(access_pattern, "random") != 0) {
        printf("Error: access_pattern must be 'sequential' or 'random'\n");
        return 1;
    }

    size_t alloc_size_bytes = (size_t)size_mb * 1024 * 1024;
    int num_pages = alloc_size_bytes / PAGE_SIZE;
    
    struct timespec start, end;
    void *ptr;
    long duration_ns;
    int i;
    
    // Allocate anonymous memory
    ptr = mmap(NULL, alloc_size_bytes, PROT_READ | PROT_WRITE, 
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    if (ptr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    
    // Prepare page indices array
    int *page_indices = malloc(num_pages * sizeof(int));
    if (!page_indices) {
        perror("malloc failed");
        munmap(ptr, alloc_size_bytes);
        return 1;
    }
    
    for (i = 0; i < num_pages; i++) {
        page_indices[i] = i;
    }
    
    // Shuffle for random access, keep sequential for sequential access
    if (strcmp(access_pattern, "random") == 0) {
        shuffle_array(page_indices, num_pages);
    }
    
    // Start timing and touch first byte in each page
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (i = 0; i < num_pages; i++) {
        int page_offset = page_indices[i] * PAGE_SIZE;
        *((char*)ptr + page_offset) = 1;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + 
                  (end.tv_nsec - start.tv_nsec);
    
    printf("%ld\n", duration_ns);
    
    // Clean up
    free(page_indices);
    munmap(ptr, alloc_size_bytes);
    
    return 0;
}
