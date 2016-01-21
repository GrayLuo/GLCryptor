//
//  ViewController.m
//  GLCryptor
//
//  Created by Grey.Luo on 16/1/21.
//  Copyright © 2016年 Grey.Luo. All rights reserved.
//

#import "ViewController.h"
#import "GLCryptor.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSString *orgString = @"http://grayluo.github.io/WeiFocusIo/";
    NSString *key = @"1234567890123456";//key must be 16 bits length
    NSString *iv = @"0p9o1q2w";
    NSString *encodeString = [GLCryptor encryptString:orgString key:key iv:iv];

    NSLog(@"orgString:%@",orgString);
    NSLog(@"encodeString:%@",encodeString);

    NSString *decodeString = [GLCryptor decryptString:encodeString key:key iv:iv];
    NSLog(@"decodeString:%@",decodeString);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
