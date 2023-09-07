//import Foundation
////import OpenSSL
//
//// Define BN_ULONG constant
//public typealias BN_ULONG = UInt
//
//// Wrapper struct for BIGNUM
//public struct BigNum {
//    fileprivate var bignum: OpaquePointer?
//
//    // Initialize a new BigNum
//    public init() {
//        bignum = BN_new()
//    }
//
//    // Initialize a BigNum from an existing OpaquePointer
//    public init(_ pointer: OpaquePointer?) {
//        bignum = pointer
//    }
//
//    // Initialize a BigNum from an integer value
//    public init(integer: Int) {
//        bignum = BN_new()
//        let bnInt = BN_new()
//        BN_set_word(bnInt, BN_ULONG(integer))
//        BN_copy(bignum, bnInt)
//        BN_free(bnInt)
//    }
//
//    // Initialize a BigNum from a hexadecimal string
//    public init(hexString: String) {
//        bignum = BN_new()
//        let hexCString = hexString.cString(using: .utf8)
//        BN_hex2bn(&bignum, hexCString)
//    }
//
//    // Get the hexadecimal representation of the BigNum
//    public var hexString: String {
//        let hexCString = BN_bn2hex(bignum)
//        defer { free(hexCString) }
//        return String(cString: hexCString!)
//    }
//
//    // Perform addition of two BigNums
//    public static func + (left: BigNum, right: BigNum) -> BigNum {
//        let result = BigNum()
//        BN_add(result.bignum, left.bignum, right.bignum)
//        return result
//    }
//
//    // Add two BigNums and store the result in the left BigNum
//    public static func += (left: inout BigNum, right: BigNum) {
//        BN_add(left.bignum, left.bignum, right.bignum)
//    }
//}
