#include "MetalResource.h"

@implementation VulkanBuffer
- (MTLStorageMode) storageMode
{
    return MTLStorageModeManaged;
}

- (MTLHazardTrackingMode) hazardTrackingMode
{
    return MTLHazardTrackingModeDefault;
}
-(int) heapOffset {
return 0;
}

-(int)allocatedSize
{
    return 0;
}
@end


@implementation VulkanTexture
- (int) bufferOffset 
{
    return 0;
}
- (int)isShareable {
    return 0;
}
-(id<MTLTexture> _Nullable) parentTexture
{
    return nil;
}
@end