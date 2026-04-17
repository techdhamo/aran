// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT double AranVersionNumber;
FOUNDATION_EXPORT const unsigned char AranVersionString[];

// Low-level C engine
#import <Aran/AranCore.h>

// Genesis Anchor — white-box obfuscated fallback config
#import <Aran/AranGenesis.h>

// Zero-Knowledge TLS Pin Validator
#import <Aran/AranPinValidator.h>

// ObjC anti-swizzling engine
#import <Aran/AranObjcChecker.h>
