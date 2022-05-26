#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "SecureStorage.h"
#import <Cordova/CDV.h>
#import "SAMKeychain.h"

@implementation SecureStorage

- (void)init:(CDVInvokedUrlCommand*)command
{
    CFTypeRef accessibility;
    NSString *keychainAccessibility;
    NSDictionary *keychainAccesssibilityMapping;

    ///check device has passcode
    NSData* secret = [@"Device has passcode set?" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *attributes = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService: @"LocalDeviceServices",  (__bridge id)kSecAttrAccount: @"NoAccount", (__bridge id)kSecValueData: secret, (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    if (status == errSecSuccess) { // item added okay, passcode has been set            
    SecItemDelete((__bridge CFDictionaryRef)attributes);
            if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 8.0){
          keychainAccesssibilityMapping = [NSDictionary dictionaryWithObjectsAndKeys:
              (__bridge id)(kSecAttrAccessibleAfterFirstUnlock), @"afterfirstunlock",
              (__bridge id)(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly), @"afterfirstunlockthisdeviceonly",
              (__bridge id)(kSecAttrAccessibleWhenUnlocked), @"whenunlocked",
              (__bridge id)(kSecAttrAccessibleWhenUnlockedThisDeviceOnly), @"whenunlockedthisdeviceonly",
              (__bridge id)(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly), @"whenpasscodesetthisdeviceonly",
              nil];
    } else {
          keychainAccesssibilityMapping = [NSDictionary dictionaryWithObjectsAndKeys:
              (__bridge id)(kSecAttrAccessibleAfterFirstUnlock), @"afterfirstunlock",
              (__bridge id)(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly), @"afterfirstunlockthisdeviceonly",
              (__bridge id)(kSecAttrAccessibleWhenUnlocked), @"whenunlocked",
              (__bridge id)(kSecAttrAccessibleWhenUnlockedThisDeviceOnly), @"whenunlockedthisdeviceonly",
              nil];
    }


    keychainAccessibility = [[self.commandDelegate.settings objectForKey:[@"KeychainAccessibility" lowercaseString]] lowercaseString];
    if (keychainAccessibility == nil) {
        [self successWithMessage: nil : command.callbackId];
    } else {
        if ([keychainAccesssibilityMapping objectForKey:(keychainAccessibility)] != nil) {
            accessibility = (__bridge CFTypeRef)([keychainAccesssibilityMapping objectForKey:(keychainAccessibility)]);
            [SAMKeychain setAccessibilityType:accessibility];
            [self successWithMessage: nil : command.callbackId];
        } else {
            [self failWithMessage: @"Unrecognized KeychainAccessibility value in config" : nil : command.callbackId];
        }
    }
    }
    else
    {
         [self failWithMessage: @"Device is not secure" : nil : command.callbackId];
    }
}

- (void)get:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SAMKeychainQuery *query = [[SAMKeychainQuery alloc] init];
        query.service = service;
        query.account = key;

        if ([query fetch:&error]) {
            [self successWithMessage: query.password : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.get()" : error : command.callbackId];
        }
    }];
}

- (void)set:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    NSString *value = [command argumentAtIndex:2];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SAMKeychainQuery *query = [[SAMKeychainQuery alloc] init];
        query.service = service;
        query.account = key;
        query.password = value;

        if ([query save:&error]) {
            [self successWithMessage: key : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.set()" : error : command.callbackId];
        }
    }];
}

- (void)remove:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SAMKeychainQuery *query = [[SAMKeychainQuery alloc] init];
        query.service = service;
        query.account = key;

        if ([query deleteItem:&error]) {
            [self successWithMessage: key : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.remove()" : error : command.callbackId];
        }
    }];
}

- (void)keys:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SAMKeychainQuery *query = [[SAMKeychainQuery alloc] init];
        query.service = service;

        NSArray *accounts = [query fetchAll:&error];
        if (accounts) {
            NSMutableArray *array = [NSMutableArray arrayWithCapacity:[accounts count]];
            for (id dict in accounts) {
                [array addObject:[dict valueForKeyPath:@"acct"]];
            }

            CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:array];
            [self.commandDelegate sendPluginResult:commandResult callbackId:command.callbackId];
        } else if ([error code] == errSecItemNotFound) {
            CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:[NSArray array]];
            [self.commandDelegate sendPluginResult:commandResult callbackId:command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.keys()" : error : command.callbackId];
        }
    }];
}

- (void)clear:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SAMKeychainQuery *query = [[SAMKeychainQuery alloc] init];
        query.service = service;

        NSArray *accounts = [query fetchAll:&error];
        if (accounts) {
            for (id dict in accounts) {
                query.account = [dict valueForKeyPath:@"acct"];
                if (![query deleteItem:&error]) {
                    break;
                }
            }

            if (!error) {
                [self successWithMessage: nil : command.callbackId];
            } else {
                [self failWithMessage: @"Failure in SecureStorage.clear()" : error : command.callbackId];
            }

        } else if ([error code] == errSecItemNotFound) {
            [self successWithMessage: nil : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.clear()" : error : command.callbackId];
        }

    }];
}

-(void)successWithMessage:(NSString *)message : (NSString *)callbackId
{
        CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message];
        [self.commandDelegate sendPluginResult:commandResult callbackId:callbackId];
}

-(void)failWithMessage:(NSString *)message : (NSError *)error : (NSString *)callbackId
{
    NSString        *errorMessage = (error) ? [NSString stringWithFormat:@"%@ - %@", message, [error localizedDescription]] : message;
    CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];

    [self.commandDelegate sendPluginResult:commandResult callbackId:callbackId];
}

@end
