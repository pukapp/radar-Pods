//
//  Copyright (c) 2019 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (keyVersionByte)

- (instancetype)prependKeyType;

- (instancetype)throws_removeKeyType;
- (nullable instancetype)removeKeyTypeAndReturnError:(NSError **)outError;

@end

NS_ASSUME_NONNULL_END
