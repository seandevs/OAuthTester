//
//  testViewController.m
//  TestApp
//
//  Created by Dhanesh Neela Mana on 4/18/14.
//  Copyright (c) 2014 Dhanesh Neela Mana. All rights reserved.
//

#import "testViewController.h"
#import "NSString+URLEncoding.h"
#import "CommonCrypto/CommonHMAC.h"
#include "Base64Transcoder.h"
typedef void (^WebWiewDelegateHandler)(NSDictionary *oauthParams);
// Go to: https://www.linkedin.com/secure/developer and get your API keys

#define OAUTH_CALLBACK       @"linkedin_oauth" //Sometimes this has to be the same as the registered app callback url
#define CONSUMER_KEY         @"Key"
#define AUTH_URL             @"http://owner-pc:36931/login.aspx"
#define REQUEST_TOKEN_URL    @"/token/request_token"
#define AUTHENTICATE_URL     @"oauth/authorize"
#define ACCESS_TOKEN_URL     @"oauth/accessToken"
#define API_URL              @"http://owner-pc:36931"
#define REQUEST_TOKEN_METHOD @"POST"
#define ACCESS_TOKEN_METHOD  @"POST"

//--- The part below is from AFNetworking---
static NSString * CHPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kCHCharactersToBeEscaped = @":/?&=;+!@#$()~";
    static NSString * const kCHCharactersToLeaveUnescaped = @"[].";
    
	return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kCHCharactersToLeaveUnescaped, (__bridge CFStringRef)kCHCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

#pragma mark -

@interface CHQueryStringPair : NSObject
@property (readwrite, nonatomic, strong) id field;
@property (readwrite, nonatomic, strong) id value;

- (id)initWithField:(id)field value:(id)value;

- (NSString *)URLEncodedStringValueWithEncoding:(NSStringEncoding)stringEncoding;
@end

@implementation CHQueryStringPair
@synthesize field = _field;
@synthesize value = _value;

- (id)initWithField:(id)field value:(id)value {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.field = field;
    self.value = value;
    
    return self;
}

- (NSString *)URLEncodedStringValueWithEncoding:(NSStringEncoding)stringEncoding {
    if (!self.value || [self.value isEqual:[NSNull null]]) {
        return CHPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.field description], stringEncoding);
    } else {
        return [NSString stringWithFormat:@"%@=%@", CHPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.field description], stringEncoding), CHPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.value description], stringEncoding)];
    }
}

@end

#pragma mark -

extern NSArray * CHQueryStringPairsFromDictionary(NSDictionary *dictionary);
extern NSArray * CHQueryStringPairsFromKeyAndValue(NSString *key, id value);

NSString * CHQueryStringFromParametersWithEncoding(NSDictionary *parameters, NSStringEncoding stringEncoding) {
    NSMutableArray *mutablePairs = [NSMutableArray array];
    for (CHQueryStringPair *pair in CHQueryStringPairsFromDictionary(parameters)) {
        [mutablePairs addObject:[pair URLEncodedStringValueWithEncoding:stringEncoding]];
    }
    
    return [mutablePairs componentsJoinedByString:@"&"];
}

NSArray * CHQueryStringPairsFromDictionary(NSDictionary *dictionary) {
    return CHQueryStringPairsFromKeyAndValue(nil, dictionary);
}

NSArray * CHQueryStringPairsFromKeyAndValue(NSString *key, id value) {
    NSMutableArray *mutableQueryStringComponents = [NSMutableArray array];
    
    if([value isKindOfClass:[NSDictionary class]]) {
        // Sort dictionary keys to ensure consistent ordering in query string, which is important when deserializing potentially ambiguous sequences, such as an array of dictionaries
        NSSortDescriptor *sortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"description" ascending:YES selector:@selector(caseInsensitiveCompare:)];
        [[[value allKeys] sortedArrayUsingDescriptors:[NSArray arrayWithObject:sortDescriptor]] enumerateObjectsUsingBlock:^(id nestedKey, NSUInteger idx, BOOL *stop) {
            id nestedValue = [value objectForKey:nestedKey];
            if (nestedValue) {
                [mutableQueryStringComponents addObjectsFromArray:CHQueryStringPairsFromKeyAndValue((key ? [NSString stringWithFormat:@"%@[%@]", key, nestedKey] : nestedKey), nestedValue)];
            }
        }];
    } else if([value isKindOfClass:[NSArray class]]) {
        [value enumerateObjectsUsingBlock:^(id nestedValue, NSUInteger idx, BOOL *stop) {
            [mutableQueryStringComponents addObjectsFromArray:CHQueryStringPairsFromKeyAndValue([NSString stringWithFormat:@"%@[]", key], nestedValue)];
        }];
    } else {
        [mutableQueryStringComponents addObject:[[CHQueryStringPair alloc] initWithField:key value:value]];
    }
    
    return mutableQueryStringComponents;
}



@interface testViewController ()

@end

@implementation testViewController
@synthesize label;
@synthesize consumerkey_label;
@synthesize consumersecret_label;
@synthesize token_label;
@synthesize  tokensecret_label;
@synthesize nonce_label;
@synthesize  timestamp_label;
@synthesize url_label;
@synthesize  methodname_label;
@synthesize  result_label;
@synthesize  consumerkey;
@synthesize  consumersecret;
@synthesize token;
@synthesize tokensecret;
@synthesize nonce;
@synthesize timestamp;
@synthesize url;
@synthesize methodname;
@synthesize result;
@synthesize signButton;

- (NSMutableDictionary *)standardOauthParameters:(NSString *)consumer_key
{
    NSString *oauth_timestamp = [NSString stringWithFormat:@"%i", (NSUInteger)[NSDate.date timeIntervalSince1970]];
    NSString *oauth_nonce = [NSString getNonce];
    NSString *oauth_consumer_key = consumer_key;
    NSString *oauth_signature_method = @"HMAC-SHA1";
    NSString *oauth_version = @"1.0";
    NSLog(@"DEBUG: nonce: %@", oauth_nonce);
    NSLog(@"DEBUG: timestamp: %@", oauth_timestamp);
    NSMutableDictionary *standardParameters = [NSMutableDictionary dictionary];
    [standardParameters setValue:oauth_consumer_key     forKey:@"oauth_consumer_key"];
    [standardParameters setValue:oauth_nonce            forKey:@"oauth_nonce"];
    [standardParameters setValue:oauth_signature_method forKey:@"oauth_signature_method"];
    [standardParameters setValue:oauth_timestamp        forKey:@"oauth_timestamp"];
    [standardParameters setValue:oauth_version          forKey:@"oauth_version"];
    
    return standardParameters;
}

#pragma mark build authorized API-requests
- (NSString *)GenerateSignature:(NSString *)path
                          HTTPmethod:(NSString *)HTTPmethod
                          consumerKey:(NSString *)consumer_key
                          consumerSecret:(NSString *)consumer_secret
                          oauthToken:(NSString *)oauth_token
                         oauthSecret:(NSString *)oauth_token_secret
{
    if (!HTTPmethod
        || !oauth_token) return nil;
    NSMutableDictionary *allParameters = [self standardOauthParameters:consumer_key];
    allParameters[@"oauth_token"] = oauth_token;
    NSString *parametersString = CHQueryStringFromParametersWithEncoding(allParameters, NSUTF8StringEncoding);
   
    NSString *request_url = API_URL;
    if (path) request_url = [request_url stringByAppendingString:path];
    NSString *oauth_consumer_secret = consumer_secret;
    NSString *baseString = [HTTPmethod stringByAppendingFormat:@"&%@&%@", request_url.utf8AndURLEncode, parametersString.utf8AndURLEncode];
    NSString *secretString = [oauth_consumer_secret.utf8AndURLEncode stringByAppendingFormat:@"&%@", oauth_token_secret.utf8AndURLEncode];
    NSString *oauth_signature = [self.class signClearText:baseString withSecret:secretString];
    return oauth_signature;
}
- (NSString *)GenerateSignature:(NSString *)path
                     HTTPmethod:(NSString *)HTTPmethod
                    consumerKey:(NSString *)consumer_key
                 consumerSecret:(NSString *)consumer_secret
{
    if (!HTTPmethod) return nil;
     NSLog(@"DEBUG: HTTPmethod: %@", HTTPmethod);
    NSMutableDictionary *allParameters = [self standardOauthParameters:consumer_key];
    NSString *parametersString = CHQueryStringFromParametersWithEncoding(allParameters, NSUTF8StringEncoding);
       NSString *request_url = API_URL;
       if (path) request_url = [request_url stringByAppendingString:path];
     NSLog(@"DEBUG: paramstring: %@", parametersString);
    NSString *oauth_consumer_secret = consumer_secret;
    NSString *baseString = [HTTPmethod stringByAppendingFormat:@"&%@&%@", request_url.utf8AndURLEncode, parametersString.utf8AndURLEncode];
    NSString *secretString = oauth_consumer_secret.utf8AndURLEncode;
     NSLog(@"DEBUG: basestring: %@", baseString);
    NSLog(@"DEBUG: secretstring: %@", secretString);

    NSString *oauth_signature = [self.class signClearText:baseString withSecret:secretString];
    return oauth_signature;
}

#pragma mark -
+ (NSString *)signClearText:(NSString *)text withSecret:(NSString *)secret
{
    NSString *data = text;
    const char *cKey = [secret cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [data cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    //CCHmac(kCCHmacAlgSHA1, (__bridge const void *)(secret), strlen((__bridge const void *)(secret)), (__bridge const void *)(text), strlen( (__bridge const void *)(text)), cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *signature = [HMAC base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"HMAC %@", [HMAC description]);
    NSLog(@"Signature %@", signature);
    return signature;
}
- (void)viewDidLoad
{
    self.label.text = @"Test OAuth Signature!";
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
- (IBAction) dosignButton {
	NSString *signature = [self GenerateSignature:url.text  HTTPmethod:methodname.text consumerKey:consumerkey.text consumerSecret:consumersecret.text ];
    result.text = signature;
  }
@end
