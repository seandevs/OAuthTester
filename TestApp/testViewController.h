//
//  testViewController.h
//  TestApp
//
//  Created by Dhanesh Neela Mana on 4/18/14.
//  Copyright (c) 2014 Dhanesh Neela Mana. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface testViewController : UIViewController

@property (nonatomic, retain) IBOutlet UIButton *signButton;
@property (strong, nonatomic)IBOutlet UILabel *label;
@property (strong, nonatomic)IBOutlet UILabel *consumerkey_label;
@property (strong, nonatomic)IBOutlet UILabel *consumersecret_label;
@property (strong, nonatomic)IBOutlet UILabel *token_label;
@property (strong, nonatomic)IBOutlet UILabel *tokensecret_label;
@property (strong, nonatomic)IBOutlet UILabel *nonce_label;
@property (strong, nonatomic)IBOutlet UILabel *timestamp_label;
@property (strong, nonatomic)IBOutlet UILabel *url_label;
@property (strong, nonatomic)IBOutlet UILabel *methodname_label;
@property (strong, nonatomic)IBOutlet UILabel *result_label;
@property (strong, nonatomic)IBOutlet UITextField *consumerkey;
@property (strong, nonatomic)IBOutlet UITextField *consumersecret;
@property (strong, nonatomic)IBOutlet UITextField *token;
@property (strong, nonatomic)IBOutlet UITextField *tokensecret;
@property (strong, nonatomic)IBOutlet UITextField *nonce;
@property (strong, nonatomic)IBOutlet UITextField *timestamp;
@property (strong, nonatomic)IBOutlet UITextField *url;
@property (strong, nonatomic)IBOutlet UITextField *methodname;
@property (strong,nonatomic)IBOutlet  UITextField  *result;
- (IBAction) dosignButton;

-(NSString *)GenerateSignature:(NSString *)path
                         HTTPmethod:(NSString *)method
                         consumerKey:(NSString *)consumer_key
                         consumerSecret:(NSString *)consumer_secret
                         oauthToken:(NSString *)oauth_token
                         oauthSecret:(NSString *)oauth_token_secret;
-(NSString *)GenerateSignature:(NSString *)path
                    HTTPmethod:(NSString *)HTTPmethod
                   consumerKey:(NSString *)consumer_key
                consumerSecret:(NSString *)consumer_secret;


@end
