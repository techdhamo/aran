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

import Foundation

@objc public enum ReactionPolicy: Int {
    case logOnly = 0
    case warnUser = 1
    case blockApi = 2
    case killApp = 3
    case blockAndReport = 4
    case custom = 5
    
    public var stringValue: String {
        switch self {
        case .logOnly: return "LOG_ONLY"
        case .warnUser: return "WARN_USER"
        case .blockApi: return "BLOCK_API"
        case .killApp: return "KILL_APP"
        case .blockAndReport: return "BLOCK_AND_REPORT"
        case .custom: return "CUSTOM"
        }
    }
}
