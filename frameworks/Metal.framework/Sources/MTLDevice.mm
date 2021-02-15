#import <Metal/MTLDevice.h>

#include "MetalDevicePrivate.h"

id <MTLDevice> MTLCreateSystemDefaultDevice(void)
{
    id <MTLDevice> device;
    device.name;
    return device;
}

NSArray<id<MTLDevice>>* MTLCopyAllDevices() 
{

}

// Implement mtldevice on vulkan
@implementation VulkanDevice
- (int) isDepth24Stencil8PixelFormatSupported
{
    return 0;
}
- (uint64_t) recommendedMaxWorkingSetSize
{
    return 0;
}
- (int) maxThreadgroupMemoryLength
{
    return 0;
}
- (int) isHeadless
{
    return 0;
}
- (int) isRemovable
{
    return false;
}
- (int) supportsDynamicLibraries
{
    return 0;
}
- (int) currentAllocatedSize
{
    return 0;
}
- (MTLArgumentBuffersTier) argumentBuffersSupport
{
    return MTLArgumentBuffersTier2;
}

- (NSArray<id<MTLCounterSet>> * _Nullable) counterSets
{
    return nil;
}
@end