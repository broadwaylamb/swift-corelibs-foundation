// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
// See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//

import CoreFoundation

#if os(macOS) || os(iOS)
import Darwin
#elseif os(Linux) || CYGWIN
import Glibc
#endif

#if DEPLOYMENT_ENABLE_LIBDISPATCH
import Dispatch
#endif

extension NSData {
    
    /// Options for methods used to read `NSData` objects.
    public struct ReadingOptions : OptionSet {
        
        public let rawValue : UInt
        
        public init(rawValue: UInt) { self.rawValue = rawValue }
        
        /// A hint indicating the file should be mapped into virtual memory,
        /// if possible and safe.
        public static let mappedIfSafe = ReadingOptions(rawValue: UInt(1 << 0))
    
        /// A hint indicating the file should not be stored in the file-system
        /// caches.
        public static let uncached = ReadingOptions(rawValue: UInt(1 << 1))
        
        /// Hint to map the file in if possible.
        public static let alwaysMapped = ReadingOptions(rawValue: UInt(1 << 2))
    }

    /// Options for methods used to write `NSData` objects.
    public struct WritingOptions : OptionSet {
        
        public let rawValue : UInt
        
        public init(rawValue: UInt) { self.rawValue = rawValue }
        
        /// A hint to write data to an auxiliary file first and then exchange
        /// the files. This option is equivalent to using a write method taking
        /// the parameter `atomically: true`.
        public static let atomic = WritingOptions(rawValue: UInt(1 << 0))
        
        /// Hint to return prevent overwriting an existing file.
        /// Cannot be combined with `atomic`.
        public static let withoutOverwriting = WritingOptions(rawValue: UInt(1 << 1))
    }

    /// Options for method used to search `NSData` objects. These options
    /// are used with the `range(of:options:in:)` method.
    public struct SearchOptions : OptionSet {
        
        public let rawValue : UInt
        
        public init(rawValue: UInt) { self.rawValue = rawValue }
        
        /// Search from the end of `NSData` object.
        public static let backwards = SearchOptions(rawValue: UInt(1 << 0))
        
        /// Search is limited to start (or end, if `.backwards` is set)
        /// of `NSData` object.
        public static let anchored = SearchOptions(rawValue: UInt(1 << 1))
    }

    /// Options for methods used to Base-64 encode data.
    public struct Base64EncodingOptions : OptionSet {
        
        public let rawValue : UInt
        
        public init(rawValue: UInt) { self.rawValue = rawValue }
        
        /// Set the maximum line length to 64 characters, after which a line
        /// ending is inserted.
        public static let lineLength64Characters = Base64EncodingOptions(rawValue: UInt(1 << 0))
        
        /// Set the maximum line length to 76 characters, after which a line
        /// ending is inserted.
        public static let lineLength76Characters = Base64EncodingOptions(rawValue: UInt(1 << 1))
        
        /// When a maximum line length is set, specify that the line ending
        /// to insert should include a carriage return.
        public static let endLineWithCarriageReturn = Base64EncodingOptions(rawValue: UInt(1 << 4))
        
        /// When a maximum line length is set, specify that the line ending
        /// to insert should include a line feed.
        public static let endLineWithLineFeed = Base64EncodingOptions(rawValue: UInt(1 << 5))
    }

    /// Options to modify the decoding algorithm used to decode Base-64 encoded
    /// `NSData` objects.
    public struct Base64DecodingOptions : OptionSet {
        
        public let rawValue : UInt
        
        public init(rawValue: UInt) { self.rawValue = rawValue }
        
        /// Modify the decoding algorithm so that it ignores unknown non-Base-64
        /// bytes, including line ending characters.
        public static let ignoreUnknownCharacters = Base64DecodingOptions(rawValue: UInt(1 << 0))
    }
}

private final class _NSDataDeallocator {
    var handler: (UnsafeMutableRawPointer, Int) -> Void = {_,_ in }
}

private let __kCFMutable: CFOptionFlags = 0x01
private let __kCFGrowable: CFOptionFlags = 0x02
private let __kCFMutableVarietyMask: CFOptionFlags = 0x03
private let __kCFBytesInline: CFOptionFlags = 0x04
private let __kCFUseAllocator: CFOptionFlags = 0x08
private let __kCFDontDeallocate: CFOptionFlags = 0x10
private let __kCFAllocatesCollectable: CFOptionFlags = 0x20

/// `NSData` and its mutable subclass `NSMutableData` provide data objects,
/// object-oriented wrappers for byte buffers. Data objects let simple allocated
/// buffers (that is, data with no embedded pointers) take on the behavior of
/// Foundation objects.
///
/// `NSData` creates static data objects, and `NSMutableData` creates dynamic
/// data objects. `NSData` and `NSMutableData` are typically used for data
/// storage and are also useful in Distributed Objects applications, where data
/// contained in data objects can be copied or moved between applications.
///
/// The size of the data is subject to a theoretical limit of about 8 ExaBytes
/// (in practice, the limit should not be a factor).
///
/// NSData is “toll-free bridged” with its Core Foundation counterpart,
/// `CFData`.
///
/// - Important: The Swift overlay to the Foundation framework provides
///              the `Data` structure, which bridges to the `NSData` class and
///              its mutable subclass, `NSMutableData`. The `Data` value type
///              offers the same functionality as the `NSData` reference type,
///              and the two can be used interchangeably in Swift code that
///              interacts with Objective-C APIs. This behavior is similar to
///              how Swift bridges standard string, numeric, and collection
///              types to their corresponding Foundation classes.
/// 
/// ## Saving Data
/// The `NSData` class and its subclasses provide methods to quickly and easily
/// save their contents to disk. To minimize the risk of data loss, these
/// methods provide the option of saving the data atomically. Atomic writes
/// guarantee that the data is either saved in its entirety, or it fails
/// completely. The atomic write begins by writing the data to a temporary file.
/// If this write succeeds, then the method moves the temporary file to its
/// final location.
///
/// While atomic write operations minimize the risk of data loss due to corrupt
/// or partially-written files, they may not be appropriate when writing to
/// a temporary directory, the user’s home directory or other publicly
/// accessible directories. Any time you work with a publicly accessible file,
/// you should treat that file as an untrusted and potentially dangerous
/// resource. An attacker may compromise or corrupt these files. The attacker
/// can also replace the files with hard or symbolic links, causing your write
/// operations to overwrite or corrupt other system resources.
///
/// Avoid using the `write(to:atomically:)` method (and the related methods)
/// when working inside a publicly accessible directory. Instead initialize
/// a `FileHandle` object with an existing file descriptor and use the
/// `FileHandle` methods to securely write the file.
open class NSData : NSObject, NSCopying, NSMutableCopying, NSSecureCoding {
    typealias CFType = CFData
    
    private var _base = _CFInfo(typeID: CFDataGetTypeID())
    private var _length: CFIndex = 0
    private var _capacity: CFIndex = 0
    private var _deallocator: UnsafeMutableRawPointer? = nil // for CF only
    private var _deallocHandler: _NSDataDeallocator? = _NSDataDeallocator() // for Swift
    private var _bytes: UnsafeMutablePointer<UInt8>? = nil
    
    internal var _cfObject: CFType {
        if type(of: self) === NSData.self || type(of: self) === NSMutableData.self {
            return unsafeBitCast(self, to: CFType.self)
        } else {
            let bytePtr = self.bytes.bindMemory(to: UInt8.self, capacity: self.length)
            return CFDataCreate(kCFAllocatorSystemDefault, bytePtr, self.length)
        }
    }
    
    internal func _providesConcreteBacking() -> Bool {
        return type(of: self) === NSData.self || type(of: self) === NSMutableData.self
    }
    
    override open var _cfTypeID: CFTypeID {
        return CFDataGetTypeID()
    }

    // NOTE: the deallocator block here is implicitly @escaping by virtue of it being optional     
    public init(bytes: UnsafeMutableRawPointer?, length: Int, copy: Bool = false, deallocator: ((UnsafeMutableRawPointer, Int) -> Void)? = nil) {
        super.init()
        let options : CFOptionFlags = (type(of: self) == NSMutableData.self) ? __kCFMutable | __kCFGrowable : 0x0
        let bytePtr = bytes?.bindMemory(to: UInt8.self, capacity: length)
        if copy {
            _CFDataInit(unsafeBitCast(self, to: CFMutableData.self), options, length, bytePtr, length, false)
            if let handler = deallocator {
                handler(bytes!, length)
            }
        } else {
            if let handler = deallocator {
                _deallocHandler!.handler = handler
            }
            // The data initialization should flag that CF should not deallocate which leaves the handler a chance to deallocate instead
            _CFDataInit(unsafeBitCast(self, to: CFMutableData.self), options | __kCFDontDeallocate, length, bytePtr, length, true)
        }
    }
    
    public override convenience init() {
        let dummyPointer = unsafeBitCast(NSData.self, to: UnsafeMutableRawPointer.self)
        self.init(bytes: dummyPointer, length: 0, copy: false, deallocator: nil)
    }
    
    /// Initializes a data object by adding to it a given number
    /// of bytes of data copied from a given buffer.
    ///
    /// A data object initialized by adding to it `length` bytes of data copied
    /// from the buffer `bytes`. The returned object might be different than
    /// the original receiver.
    ///
    /// - Parameters:
    ///   - bytes:  A buffer containing data for the new object.
    ///   - length: The number of bytes to hold from `bytes`. This value must not
    ///             exceed the length of `bytes`.
    public convenience init(bytes: UnsafeRawPointer?, length: Int) {
        self.init(bytes: UnsafeMutableRawPointer(mutating: bytes), length: length, copy: true, deallocator: nil)
    }
    
    /// Initializes a data object by adding to it a given number
    /// of bytes of data from a given buffer.
    ///
    /// - Parameters:
    ///   - bytes:  A buffer containing data for the new object. `bytes` must
    ///             point to a memory block allocated with `malloc`.
    ///   - length: The number of bytes to hold from `bytes`. This value must not
    ///             exceed the length of `bytes`.
    public convenience init(bytesNoCopy bytes: UnsafeMutableRawPointer, length: Int) {
        self.init(bytes: bytes, length: length, copy: false, deallocator: nil)
    }
    
    /// Initializes a newly allocated data object by adding to it `length`
    /// bytes of data from the buffer `bytes`.
    ///
    /// - Parameters:
    ///   - bytes:  A buffer containing data for the new object. If `b` is true,
    ///            `bytes` must point to a memory block allocated with `malloc`.
    ///   - length: The number of bytes to hold from `bytes`. This value must
    ///             not exceed the length of `bytes`.
    ///   - b:      If `true`, the initialized object takes ownership of
    ///             the `bytes` pointer and frees it on deallocation.
    public convenience init(bytesNoCopy bytes: UnsafeMutableRawPointer, length: Int, freeWhenDone b: Bool) {
        self.init(bytes: bytes, length: length, copy: false) { buffer, length in
            if b {
                free(buffer)
            }
        }
    }

    /// Initializes a data object by adding to it a given number of
    /// bytes of data from a given buffer, with a custom deallocator block.
    ///
    /// Use this method to define your own deallocation behavior for the data
    /// buffer you provide.
    ///
    /// - Note: The deallocator block here is implicitly `@escaping` by virtue
    ///         of it being optional. In order to avoid any inadvertent strong
    ///         reference cycles, you should avoid capturing pointers to any
    ///         objects that may in turn maintain strong references to the
    ///         `NSData` object. This includes explicit references to `self`,
    ///         and implicit references to `self` due to direct instance
    ///         variable access. To make it easier to avoid these references,
    ///         the deallocator block takes two parameters, a pointer to the
    ///         buffer, and its length; you should always use these values
    ///         instead of trying to use references from outside the block.
    ///
    /// - Parameters:
    ///   - bytes:          A buffer containing data for the new object.
    ///   - length:         The number of bytes to hold from `bytes`. This value
    ///                     must not exceed the length of `bytes`.
    ///   - deallocator:    A block to invoke when the resulting `NSData` object
    ///                     is deallocated.
    public convenience init(bytesNoCopy bytes: UnsafeMutableRawPointer, length: Int, deallocator: ((UnsafeMutableRawPointer, Int) -> Void)? = nil) {
        self.init(bytes: bytes, length: length, copy: false, deallocator: deallocator)
    }
    
    /// Initializes a data object by reading into it the data from the file
    /// specified by a given path.
    ///
    /// - Parameters:
    ///   - path:            The absolute path of the file from which to read
    ///                      data.
    ///   - readOptionsMask: A mask that specifies options for reading the data
    ///                      Constant components are described in
    ///                      `NSData.ReadingOptions`.
    /// - Throws: An `NSError` object that describes the problem.
    public convenience init(contentsOfFile path: String, options readOptionsMask: ReadingOptions = []) throws {
        let readResult = try NSData.readBytesFromFileWithExtendedAttributes(path, options: readOptionsMask)
        self.init(bytes: readResult.bytes, length: readResult.length, copy: false, deallocator: readResult.deallocator)
    }
    
    /// Initializes a data object by reading into it the data from the file
    /// specified by a given path.
    ///
    /// This method is equivalent to `init(contentsOfFile:options:)` with no
    /// options.
    ///
    /// - Parameter path: The absolute path of the file from which to read data.
    public convenience init?(contentsOfFile path: String) {
        do {
            let readResult = try NSData.readBytesFromFileWithExtendedAttributes(path, options: [])
            self.init(bytes: readResult.bytes, length: readResult.length, copy: false, deallocator: readResult.deallocator)
        } catch {
            return nil
        }
    }
    
    /// Initializes a data object with the contents of another data object.
    ///
    /// - Parameter data: A data object.
    public convenience init(data: Data) {
        self.init(bytes: data._nsObject.bytes, length: data.count)
    }
    
    /// Initializes a data object with the data from the location specified by
    /// a given URL.
    ///
    /// - Parameters:
    ///   - url:                The URL from which to read data.
    ///   - readOptionsMask:    A mask that specifies options for reading
    ///                         the data. Constant components are described in
    ///                         `NSData.ReadingOptions`.
    /// - Throws:  An `NSError` object that describes the problem if there is
    ///            an error reading in the data.
    public convenience init(contentsOf url: URL, options readOptionsMask: ReadingOptions = []) throws {
        if url.isFileURL {
            try self.init(contentsOfFile: url.path, options: readOptionsMask)
        } else {
            let session = URLSession(configuration: URLSessionConfiguration.default)
            let cond = NSCondition()
            var resError: Error?
            var resData: Data?
            let task = session.dataTask(with: url, completionHandler: { data, response, error in
                resData = data
                resError = error
                cond.broadcast()
            })
            task.resume()
            cond.wait()
            guard let data = resData else {
                throw resError!
            }
            self.init(data: data)
        }
    }
    
    /// Initializes a data object with the given Base-64 encoded string,
    /// or returns nil if the data object could not be decoded.
    ///
    /// The default implementation of this method will reject non-alphabet
    /// characters, including line break characters. To support different
    /// encodings and ignore non-alphabet characters, specify an options value
    /// of `ignoreUnknownCharacters`.
    ///
    /// - Parameters:
    ///   - base64String:   A Base-64 encoded string.
    ///   - options:        A mask that specifies options for Base-64 decoding
    ///                     the data. Possible values are given in
    ///                     `NSData.Base64DecodingOptions`.
    public convenience init?(base64Encoded base64String: String, options: Base64DecodingOptions = []) {
        let encodedBytes = Array(base64String.utf8)
        guard let decodedBytes = NSData.base64DecodeBytes(encodedBytes, options: options) else {
            return nil
        }
        self.init(bytes: decodedBytes, length: decodedBytes.count)
    }
    
    
    /// Returns a data object initialized with the given Base-64 encoded data,
    //// or returns nil if the data object could not be decoded.
    ///
    /// The default implementation of this method will reject non-alphabet
    /// characters, including line break characters. To support different
    /// encodings and ignore non-alphabet characters, specify an options value
    /// of `ignoreUnknownCharacters`.
    ///
    /// - Parameters:
    ///   - base64Data: A Base-64, UTF-8 encoded data object.
    ///   - options:    A mask that specifies options for Base-64 decoding
    ///                 the data. Possible values are given in
    ///                 `NSData.Base64DecodingOptions`.
    public convenience init?(base64Encoded base64Data: Data, options: Base64DecodingOptions = []) {
        var encodedBytes = [UInt8](repeating: 0, count: base64Data.count)
        base64Data._nsObject.getBytes(&encodedBytes, length: encodedBytes.count)
        guard let decodedBytes = NSData.base64DecodeBytes(encodedBytes, options: options) else {
            return nil
        }
        self.init(bytes: decodedBytes, length: decodedBytes.count)
    }
    
    deinit {
        if let allocatedBytes = _bytes {
            _deallocHandler?.handler(allocatedBytes, _length)
        }
        if type(of: self) === NSData.self || type(of: self) === NSMutableData.self {
            _CFDeinit(self._cfObject)
        }
    }
    
    // MARK: - Funnel methods
    
    /// The number of bytes contained by the data object.
    open var length: Int {
        return CFDataGetLength(_cfObject)
    }
    
    /// A pointer to the data object's contents.
    ///
    /// If the length of the `NSData` object is 0, this property returns `nil`.
    ///
    /// For an immutable data object, the returned pointer is valid until
    /// the data object is deallocated. For a mutable data object, the returned
    /// pointer is valid until the data object is deallocated or the data is
    /// mutated.
    open var bytes: UnsafeRawPointer {
        guard let bytePtr = CFDataGetBytePtr(_cfObject) else {
            //This could occure on empty data being encoded.
            //TODO: switch with nil when signature is fixed
            return UnsafeRawPointer(bitPattern: 0x7f00dead)! //would not result in 'nil unwrapped optional'
        }
        return UnsafeRawPointer(bytePtr)
    }

    // MARK: - NSObject methods
    
    /// Returns an integer that can be used as a table address in a hash table
    /// structure.
    ///
    /// If two objects are equal (as determined by the `isEqual(_:)` method),
    /// they must have the same hash value. This last point is particularly
    ///important if you define `hash` in a subclass and intend to put instances
    /// of that subclass into a collection.
    ///
    /// If a mutable object is added to a collection that uses hash values to
    /// determine the object’s position in the collection, the value returned
    /// by the `hash` property of the object must not change while the object is
    /// in the collection. Therefore, either the `hash` property must not rely
    /// on any of the object’s internal state information or you must make sure
    /// the object’s internal state information does not change while the object
    /// is in the collection. Thus, for example, a mutable dictionary can be put
    /// in a hash table but you must not change it while it is in there.
    /// (Note that it can be difficult to know whether or not a given object is
    /// in a collection.)
    open override var hash: Int {
        return Int(bitPattern: CFHash(_cfObject))
    }
    
    /// Returns a Boolean value that indicates whether the instance is equal to
    /// another given object.
    ///
    /// - Parameter object: The object with which to compare the instance.
    /// - Returns:          `true` if the instance is equal to `object`,
    ///                     otherwise `false`.
    open override func isEqual(_ value: Any?) -> Bool {
        if let data = value as? Data {
            return isEqual(to: data)
        } else if let data = value as? NSData {
            return isEqual(to: data._swiftObject)
        }
        
#if DEPLOYMENT_ENABLE_LIBDISPATCH
        if let data = value as? DispatchData {
            if data.count != length {
                return false
            }
            return data.withUnsafeBytes { (bytes2: UnsafePointer<UInt8>) -> Bool in
                let bytes1 = bytes
                return memcmp(bytes1, bytes2, length) == 0
            }
        }
#endif
        
        return false
    }
    
    /// Compares the data object to `other` data object.
    ///
    /// Two data objects are equal if they hold the same number of bytes,
    /// and if the bytes at the same position in the objects are the same.
    ///
    /// - Parameter other:  The data object with which to compare the instance.
    /// - Returns:          `true` if the contents of `other` are equal to
    ///                     the contents of the instance, otherwise `false`.
    open func isEqual(to other: Data) -> Bool {
        if length != other.count {
            return false
        }
        
        return other.withUnsafeBytes { (bytes2: UnsafePointer<UInt8>) -> Bool in
            let bytes1 = bytes
            return memcmp(bytes1, bytes2, length) == 0
        }
    }
    
    /// Returns the object returned by `copy(with:)`.
    ///
    /// - Returns: The object returned by the `NSCopying` protocol method
    ///            `copy(with:)`.
    open override func copy() -> Any {
        return copy(with: nil)
    }
    
    /// Returns a new instance that’s a copy of the current one.
    ///
    /// - Parameter zone:   This parameter is ignored. Memory zones are no
    ///                     longer used.
    /// - Returns:          A new instance that’s a copy of the current one.
    open func copy(with zone: NSZone? = nil) -> Any {
        return self
    }
    
    /// Returns the object returned by `mutableCopy(with:)` where the zone is
    /// `nil.`
    ///
    /// - Returns: The object returned by the `NSMutableCopying` protocol method
    ///            `mutableCopy(with:)`, where the zone is `nil`.
    open override func mutableCopy() -> Any {
        return mutableCopy(with: nil)
    }
    
    /// Returns a new `NSMutableData` instance that’s a mutable copy of the
    /// current one.
    ///
    /// - Parameter zone:   This parameter is ignored. Memory zones are no
    ///                     longer used.
    /// - Returns:          A new instance that’s a mutable copy of the current one.
    open func mutableCopy(with zone: NSZone? = nil) -> Any {
        return NSMutableData(bytes: UnsafeMutableRawPointer(mutating: bytes), length: length, copy: true, deallocator: nil)
    }
    
    private func byteDescription(limit: Int? = nil) -> String {
        var s = ""
        var i = 0
        while i < self.length {
            if i > 0 && i % 4 == 0 {
                // if there's a limit, and we're at the barrier where we'd add the ellipses, don't add a space.
                if let limit = limit, self.length > limit && i == self.length - (limit / 2) { /* do nothing */ }
                else { s += " " }
            }
            let byte = bytes.load(fromByteOffset: i, as: UInt8.self)
            var byteStr = String(byte, radix: 16, uppercase: false)
            if byte <= 0xf { byteStr = "0\(byteStr)" }
            s += byteStr
            // if we've hit the midpoint of the limit, skip to the last (limit / 2) bytes.
            if let limit = limit, self.length > limit && i == (limit / 2) - 1 {
                s += " ... "
                i = self.length - (limit / 2)
            } else {
                i += 1
            }
        }
        return s
    }
    
    /// Returns a string that describes the contents of the instance
    /// for presentation in the debugger.
    override open var debugDescription: String {
        return "<\(byteDescription(limit: 1024))>"
    }
    
    /// Returns a string that describes the contents of the instance.
    override open var description: String {
        return "<\(byteDescription())>"
    }
    
    // MARK: - NSCoding methods
    
    /// Encodes the data object using a given archiver.
    ///
    /// - Parameter aCoder: An archiver object.
    open func encode(with aCoder: NSCoder) {
        if let aKeyedCoder = aCoder as? NSKeyedArchiver {
            aKeyedCoder._encodePropertyList(self, forKey: "NS.data")
        } else {
            let bytePtr = self.bytes.bindMemory(to: UInt8.self, capacity: self.length)
            aCoder.encodeBytes(bytePtr, length: self.length)
        }
    }
    
    /// Initializes a data object from data in a given unarchiver.
    ///
    /// - Parameter aDecoder: An unarchiver object.
    public required convenience init?(coder aDecoder: NSCoder) {
        guard aDecoder.allowsKeyedCoding else {
            preconditionFailure("Unkeyed coding is unsupported.")
        }
        if type(of: aDecoder) == NSKeyedUnarchiver.self || aDecoder.containsValue(forKey: "NS.data") {
            guard let data = aDecoder._decodePropertyListForKey("NS.data") as? NSData else {
                return nil
            }
            self.init(data: data._swiftObject)
        } else {
            let result : Data? = aDecoder.withDecodedUnsafeBufferPointer(forKey: "NS.bytes") {
                guard let buffer = $0 else { return nil }
                return Data(buffer: buffer)
            }
            
            guard let r = result else { return nil }
            self.init(data: r)
        }
    }
    
    public static var supportsSecureCoding: Bool {
        return true
    }

    // MARK: - IO
    internal struct NSDataReadResult {
        var bytes: UnsafeMutableRawPointer
        var length: Int
        var deallocator: ((_ buffer: UnsafeMutableRawPointer, _ length: Int) -> Void)?
    }
    
    internal static func readBytesFromFileWithExtendedAttributes(_ path: String, options: ReadingOptions) throws -> NSDataReadResult {
        let fd = _CFOpenFile(path, O_RDONLY)
        if fd < 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: nil)
        }
        defer {
            close(fd)
        }

        var info = stat()
        let ret = withUnsafeMutablePointer(to: &info) { infoPointer -> Bool in
            if fstat(fd, infoPointer) < 0 {
                return false
            }
            return true
        }
        
        if !ret {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: nil)
        }
        
        let length = Int(info.st_size)
        
        if options.contains(.alwaysMapped) {
            let data = mmap(nil, length, PROT_READ, MAP_PRIVATE, fd, 0)
            
            // Swift does not currently expose MAP_FAILURE
            if data != UnsafeMutableRawPointer(bitPattern: -1) {
                return NSDataReadResult(bytes: data!, length: length) { buffer, length in
                    munmap(buffer, length)
                }
            }
            
        }
        
        let data = malloc(length)!
        var remaining = Int(info.st_size)
        var total = 0
        while remaining > 0 {
            let amt = read(fd, data.advanced(by: total), remaining)
            if amt < 0 {
                break
            }
            remaining -= amt
            total += amt
        }

        if remaining != 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: nil)
        }
        
        return NSDataReadResult(bytes: data, length: length) { buffer, length in
            free(buffer)
        }
    }
    
    internal func makeTemporaryFile(inDirectory dirPath: String) throws -> (Int32, String) {
        let template = dirPath._nsObject.appendingPathComponent("tmp.XXXXXX")
        let maxLength = Int(PATH_MAX) + 1
        var buf = [Int8](repeating: 0, count: maxLength)
        let _ = template._nsObject.getFileSystemRepresentation(&buf, maxLength: maxLength)
        let fd = mkstemp(&buf)
        if fd == -1 {
            throw _NSErrorWithErrno(errno, reading: false, path: dirPath)
        }
        let pathResult = FileManager.default.string(withFileSystemRepresentation:buf, length: Int(strlen(buf)))
        return (fd, pathResult)
    }

    internal class func write(toFileDescriptor fd: Int32, path: String? = nil, buf: UnsafeRawPointer, length: Int) throws {
        var bytesRemaining = length
        while bytesRemaining > 0 {
            var bytesWritten : Int
            repeat {
                #if os(OSX) || os(iOS)
                    bytesWritten = Darwin.write(fd, buf.advanced(by: length - bytesRemaining), bytesRemaining)
                #elseif os(Linux) || os(Android) || CYGWIN
                    bytesWritten = Glibc.write(fd, buf.advanced(by: length - bytesRemaining), bytesRemaining)
                #endif
            } while (bytesWritten < 0 && errno == EINTR)
            if bytesWritten <= 0 {
                throw _NSErrorWithErrno(errno, reading: false, path: path)
            } else {
                bytesRemaining -= bytesWritten
            }
        }
    }
    
    /// Writes the bytes in the data object to the file specified by a given
    /// path.
    ///
    /// This method may not be appropriate when writing to publicly accessible
    /// files. To securely write data to a public location, use `FileHandle`
    /// instead.
    ///
    /// - Parameters:
    ///   - path:             The location to which to write the object's bytes.
    ///   - writeOptionsMask: A mask that specifies options for writing
    ///                       the data. Constant components are described in
    ///                       `NSData.WritingOptions`.
    /// - Throws: An `NSError` object that describes the problem.
    open func write(toFile path: String, options writeOptionsMask: WritingOptions = []) throws {
        var fd : Int32
        var mode : mode_t? = nil
        let useAuxiliaryFile = writeOptionsMask.contains(.atomic)
        var auxFilePath : String? = nil
        if useAuxiliaryFile {
            // Preserve permissions.
            var info = stat()
            if lstat(path, &info) == 0 {
                mode = mode_t(info.st_mode)
            } else if errno != ENOENT && errno != ENAMETOOLONG {
                throw _NSErrorWithErrno(errno, reading: false, path: path)
            }
            let (newFD, path) = try self.makeTemporaryFile(inDirectory: path._nsObject.deletingLastPathComponent)
            fd = newFD
            auxFilePath = path
            fchmod(fd, 0o666)
        } else {
            var flags = O_WRONLY | O_CREAT | O_TRUNC
            if writeOptionsMask.contains(.withoutOverwriting) {
                flags |= O_EXCL
            }
            fd = _CFOpenFileWithMode(path, flags, 0o666)
        }
        if fd == -1 {
            throw _NSErrorWithErrno(errno, reading: false, path: path)
        }
        defer {
            close(fd)
        }

        try self.enumerateByteRangesUsingBlockRethrows { (buf, range, stop) in
            if range.length > 0 {
                do {
                    try NSData.write(toFileDescriptor: fd, path: path, buf: buf, length: range.length)
                    if fsync(fd) < 0 {
                        throw _NSErrorWithErrno(errno, reading: false, path: path)
                    }
                } catch let err {
                    if let auxFilePath = auxFilePath {
                        do {
                            try FileManager.default.removeItem(atPath: auxFilePath)
                        } catch _ {}
                    }
                    throw err
                }
            }
        }
        if let auxFilePath = auxFilePath {
            if rename(auxFilePath, path) != 0 {
                do {
                    try FileManager.default.removeItem(atPath: auxFilePath)
                } catch _ {}
                throw _NSErrorWithErrno(errno, reading: false, path: path)
            }
            if let mode = mode {
                chmod(path, mode)
            }
        }
    }
    
    /// Writes the bytes in the data object to the file specified by a given
    /// path.
    ///
    /// This method may not be appropriate when writing to publicly accessible
    /// files. To securely write data to a public location, use `FileHandle`
    /// instead.
    ///
    /// - Parameters:
    ///   - path:               The location to which to write the object's
    ///                         bytes. If path contains a tilde (~) character,
    ///                         you must expand it with `expandingTildeInPath`
    ///                         before invoking this method.
    ///   - useAuxiliaryFile:   If `true`, the data is written to a backup file,
    ///                         and then — assuming no errors occur — the backup
    ///                         file is renamed to the name specified by `path`;
    ///                         otherwise, the data is written directly to
    ///                         `path`. `atomically` is ignored if `url` is not
    ///                         of a type that supports atomic writes.
    /// - Returns: `true` if the operation succeeds, otherwise `false`.
    open func write(toFile path: String, atomically useAuxiliaryFile: Bool) -> Bool {
        do {
            try write(toFile: path, options: useAuxiliaryFile ? .atomic : [])
        } catch {
            return false
        }
        return true
    }
    
    /// Writes the bytes in the data object to the location specified by `url`.
    ///
    /// Since at present only `file://` URLs are supported, there is no
    /// difference between this method and `write(toFile:atomically:)`, except
    /// for the type of the first argument.
    ///
    /// This method may not be appropriate when writing to publicly accessible
    /// files. To securely write data to a public location, use `FileHandle`
    /// instead.
    ///
    /// - Parameters:
    ///   - url:        The location to which to write the receiver's bytes. Only
    ///                 `file://` URLs are supported.
    ///   - atomically: If `true`, the data is written to a backup location,
    ///                 and then — assuming no errors occur — the backup
    ///                 location is renamed to the name specified by `url`;
    ///                 otherwise, the data is written directly to `url`.
    ///                 `atomically` is ignored if `url` is not of a type that
    ///                 supports atomic writes.
    /// - Returns:      `true` if the operation succeeds, otherwise `false`.
    open func write(to url: URL, atomically: Bool) -> Bool {
        if url.isFileURL {
            return write(toFile: url.path, atomically: atomically)
        }
        return false
    }

    /// Writes the bytes in the data object to the location specified by a given
    /// URL.
    ///
    /// Since at present only `file://` URLs are supported, there is no
    /// difference between this method and `write(toFile:options:)`, except for
    /// the type of the first argument.
    ///
    /// This method may not be appropriate when writing to publicly accessible
    /// files. To securely write data to a public location, use `FileHandle`
    /// instead.
    ///
    /// - Parameters:
    ///   - url:              The location to which to write the object's bytes.
    ///   - writeOptionsMask: A mask that specifies options for writing
    ///                       the data. Constant components are described in
    ///                       `NSData.WritingOptions`.
    /// - Throws: An NSError object that describes the problem.
    open func write(to url: URL, options writeOptionsMask: WritingOptions = []) throws {
        guard url.isFileURL else {
            let userInfo = [NSLocalizedDescriptionKey : "The folder at “\(url)” does not exist or is not a file URL.", // NSLocalizedString() not yet available
                            NSURLErrorKey             : url.absoluteString] as Dictionary<String, Any>
            throw NSError(domain: NSCocoaErrorDomain, code: 4, userInfo: userInfo)
        }
        try write(toFile: url.path, options: writeOptionsMask)
    }
    
    // MARK: - Bytes
    
    /// Copies a number of bytes from the start of the object's data into
    /// a given buffer.
    ///
    /// The number of bytes copied is the smaller of the `length` parameter and
    /// the `length` of the data encapsulated in the object.
    ///
    /// - Parameters:
    ///   - buffer: A buffer into which to copy data.
    ///   - length: The number of bytes from the start of the object's data to
    ///             copy to `buffer`.
    open func getBytes(_ buffer: UnsafeMutableRawPointer, length: Int) {
        let bytePtr = buffer.bindMemory(to: UInt8.self, capacity: length)
        CFDataGetBytes(_cfObject, CFRangeMake(0, length), bytePtr)
    }
    
    /// Copies a range of bytes from the object’s data into a given buffer.
    ///
    /// - Parameters:
    ///   - buffer: A buffer into which to copy data.
    ///   - range:  The range of bytes in the object's data to copy to `buffer`.
    ///             The range must lie within the range of bytes of the object's
    ///             data.
    open func getBytes(_ buffer: UnsafeMutableRawPointer, range: NSRange) {
        let bytePtr = buffer.bindMemory(to: UInt8.self, capacity: range.length)
        CFDataGetBytes(_cfObject, CFRangeMake(range.location, range.length), bytePtr)
    }
    
    /// Returns a data object containing the instance’s bytes that fall within
    /// the limits specified by a given range.
    ///
    /// - Parameter range: The range in the object from which to get the data.
    ///                    The range must not exceed the bounds of the object.
    /// - Returns: A data value containing the object’s bytes that fall within
    ///            the limits specified by range.
    open func subdata(with range: NSRange) -> Data {
        if range.length == 0 {
            return Data()
        }
        if range.location == 0 && range.length == self.length {
            return Data(referencing: self)
        }
        let p = self.bytes.advanced(by: range.location).bindMemory(to: UInt8.self, capacity: range.length)
        return Data(bytes: p, count: range.length)
    }
    
    /// Finds and returns the range of the first occurrence of the given data,
    /// within the given range, subject to given options.
    ///
    /// - Parameters:
    ///   - dataToFind:  The data for which to search.
    ///   - mask:        A mask specifying search options. Constant components
    ///                  are described in `NSData.SearchOptions`.
    ///   - searchRange: The range within the instance in which to search for
    ///                  `dataToFind`.
    /// - Returns: An `NSRange` structure giving the location and length of
    ///            `dataToFind` within `searchRange`, modulo the options in
    ///            `mask`. The range returned is relative to the start of
    ///            the searched data, not the passed-in search range.
    ///            Returns `{NSNotFound, 0}` if `dataToFind` is not found or is
    ///            empty.
    open func range(of dataToFind: Data, options mask: SearchOptions = [], in searchRange: NSRange) -> NSRange {
        let dataToFind = dataToFind._nsObject
        guard dataToFind.length > 0 else {return NSRange(location: NSNotFound, length: 0)}
        guard let searchRange = searchRange.toRange() else {fatalError("invalid range")}
        
        precondition(searchRange.upperBound <= self.length, "range outside the bounds of data")

        let basePtr = self.bytes.bindMemory(to: UInt8.self, capacity: self.length)
        let baseData = UnsafeBufferPointer<UInt8>(start: basePtr, count: self.length)[searchRange]
        let searchPtr = dataToFind.bytes.bindMemory(to: UInt8.self, capacity: dataToFind.length)
        let search = UnsafeBufferPointer<UInt8>(start: searchPtr, count: dataToFind.length)
        
        let location : Int?
        let anchored = mask.contains(.anchored)
        if mask.contains(.backwards) {
            location = NSData.searchSubSequence(search.reversed(), inSequence: baseData.reversed(),anchored : anchored).map {$0.base-search.count}
        } else {
            location = NSData.searchSubSequence(search, inSequence: baseData,anchored : anchored)
        }
        return location.map {NSRange(location: $0, length: search.count)} ?? NSRange(location: NSNotFound, length: 0)
    }
    
    private static func searchSubSequence<T : Collection, T2 : Sequence>(_ subSequence : T2, inSequence seq: T,anchored : Bool) -> T.Index? where T.Iterator.Element : Equatable, T.Iterator.Element == T2.Iterator.Element, T.SubSequence.Iterator.Element == T.Iterator.Element, T.Indices.Iterator.Element == T.Index {
        for index in seq.indices {
            if seq.suffix(from: index).starts(with: subSequence) {
                return index
            }
            if anchored {return nil}
        }
        return nil
    }
    
    internal func enumerateByteRangesUsingBlockRethrows(_ block: (UnsafeRawPointer, NSRange, UnsafeMutablePointer<Bool>) throws -> Void) throws {
        var err : Swift.Error? = nil
        self.enumerateBytes() { (buf, range, stop) -> Void in
            do {
                try block(buf, range, stop)
            } catch let e {
                err = e
            }
        }
        if let err = err {
            throw err
        }
    }

    /// Enumerate through each range of bytes in the data object using a block.
    ///
    /// The enumeration block is called once for each contiguous region of
    /// memory in the data object (once total for a contiguous `NSData` object),
    /// until either all bytes have been enumerated, or the `stop` parameter is
    /// set to `true`.
    ///
    /// - Parameter block: The block to apply to byte ranges in the array.
    ///                    The block takes three arguments:
    /// - Parameters:
    ///   - bytes:     The bytes for the current range. This pointer is valid
    ///                until the data object is deallocated.
    ///   - byteRange: The range of the current data bytes.
    ///   - stop:      A reference to a Boolean value. The block can set
    ///                the value to `true` to stop further processing of
    ///                the data. The stop argument is an out-only argument.
    ///                You should only ever set this Boolean to true within
    ///                the block.
    open func enumerateBytes(_ block: (_ bytes: UnsafeRawPointer, _ byteRange: NSRange, _ stop: UnsafeMutablePointer<Bool>) -> Void) {
        var stop = false
        withUnsafeMutablePointer(to: &stop) { stopPointer in
            if (stopPointer.pointee) {
                return
            }
            block(bytes, NSMakeRange(0, length), stopPointer)
        }
    }
    
    // MARK: - Base64 Methods

    /// Create a Base-64 encoded `String` from the data object's contents using
    /// the given options.
    ///
    /// By default, no line endings are inserted.
    ///
    /// If you specify one of the line length options (`lineLength64Characters`
    /// or `lineLength76Characters`) but don’t specify the kind of line ending
    /// to insert, the default line ending is Carriage Return + Line Feed.
    ///
    /// - Parameter options: A mask that specifies options for Base-64 encoding
    ///                      the data. Possible values are given in
    ///                      `NSData.Base64EncodingOptions`.
    /// - Returns: A Base-64 encoded string.
    open func base64EncodedString(options: Base64EncodingOptions = []) -> String {
        var decodedBytes = [UInt8](repeating: 0, count: self.length)
        getBytes(&decodedBytes, length: decodedBytes.count)
        let encodedBytes = NSData.base64EncodeBytes(decodedBytes, options: options)
        let characters = encodedBytes.map { Character(UnicodeScalar($0)) }
        return String(characters)
    }

    /// Create a Base-64, UTF-8 encoded `Data` from the data object's contents
    /// using the given options.
    ///
    /// By default, no line endings are inserted.
    ///
    /// If you specify one of the line length options (`lineLength64Characters`
    /// or `lineLength76Characters`) but don’t specify the kind of line ending
    /// to insert, the default line ending is Carriage Return + Line Feed.
    ///
    /// - Parameter options: A mask that specifies options for Base-64 encoding
    ///                      the data. Possible values are given in
    ///                      `NSData.Base64EncodingOptions`.
    /// - Returns: A Base-64, UTF-8 encoded data.
    open func base64EncodedData(options: Base64EncodingOptions = []) -> Data {
        var decodedBytes = [UInt8](repeating: 0, count: self.length)
        getBytes(&decodedBytes, length: decodedBytes.count)
        let encodedBytes = NSData.base64EncodeBytes(decodedBytes, options: options)
        return Data(bytes: encodedBytes, count: encodedBytes.count)
    }

    /// The ranges of ASCII characters that are used to encode data in Base64.
    private static let base64ByteMappings: [Range<UInt8>] = [
        65 ..< 91,      // A-Z
        97 ..< 123,     // a-z
        48 ..< 58,      // 0-9
        43 ..< 44,      // +
        47 ..< 48,      // /
    ]
    /**
     Padding character used when the number of bytes to encode is not divisible by 3
     */
    private static let base64Padding : UInt8 = 61 // =
    
    /**
     This method takes a byte with a character from Base64-encoded string
     and gets the binary value that the character corresponds to.
     
     - parameter byte:       The byte with the Base64 character.
     - returns:              Base64DecodedByte value containing the result (Valid , Invalid, Padding)
     */
    private enum Base64DecodedByte {
        case valid(UInt8)
        case invalid
        case padding
    }
    private static func base64DecodeByte(_ byte: UInt8) -> Base64DecodedByte {
        guard byte != base64Padding else {return .padding}
        var decodedStart: UInt8 = 0
        for range in base64ByteMappings {
            if range.contains(byte) {
                let result = decodedStart + (byte - range.lowerBound)
                return .valid(result)
            }
            decodedStart += range.upperBound - range.lowerBound
        }
        return .invalid
    }
    
    /**
     This method takes six bits of binary data and encodes it as a character
     in Base64.
     
     The value in the byte must be less than 64, because a Base64 character
     can only represent 6 bits.
     
     - parameter byte:       The byte to encode
     - returns:              The ASCII value for the encoded character.
     */
    private static func base64EncodeByte(_ byte: UInt8) -> UInt8 {
        assert(byte < 64)
        var decodedStart: UInt8 = 0
        for range in base64ByteMappings {
            let decodedRange = decodedStart ..< decodedStart + (range.upperBound - range.lowerBound)
            if decodedRange.contains(byte) {
                return range.lowerBound + (byte - decodedStart)
            }
            decodedStart += range.upperBound - range.lowerBound
        }
        return 0
    }
    
    
    /**
     This method decodes Base64-encoded data.
     
     If the input contains any bytes that are not valid Base64 characters,
     this will return nil.
     
     - parameter bytes:      The Base64 bytes
     - parameter options:    Options for handling invalid input
     - returns:              The decoded bytes.
     */
    private static func base64DecodeBytes(_ bytes: [UInt8], options: Base64DecodingOptions = []) -> [UInt8]? {
        var decodedBytes = [UInt8]()
        decodedBytes.reserveCapacity((bytes.count/3)*2)
        
        var currentByte : UInt8 = 0
        var validCharacterCount = 0
        var paddingCount = 0
        var index = 0
        
        
        for base64Char in bytes {
            
            let value : UInt8
            
            switch base64DecodeByte(base64Char) {
            case .valid(let v):
                value = v
                validCharacterCount += 1
            case .invalid:
                if options.contains(.ignoreUnknownCharacters) {
                    continue
                } else {
                    return nil
                }
            case .padding:
                paddingCount += 1
                continue
            }
            
            //padding found in the middle of the sequence is invalid
            if paddingCount > 0 {
                return nil
            }
            
            switch index%4 {
            case 0:
                currentByte = (value << 2)
            case 1:
                currentByte |= (value >> 4)
                decodedBytes.append(currentByte)
                currentByte = (value << 4)
            case 2:
                currentByte |= (value >> 2)
                decodedBytes.append(currentByte)
                currentByte = (value << 6)
            case 3:
                currentByte |= value
                decodedBytes.append(currentByte)
            default:
                fatalError()
            }
            
            index += 1
        }
        
        guard (validCharacterCount + paddingCount)%4 == 0 else {
            //invalid character count
            return nil
        }
        return decodedBytes
    }
    
    
    /**
     This method encodes data in Base64.
     
     - parameter bytes:      The bytes you want to encode
     - parameter options:    Options for formatting the result
     - returns:              The Base64-encoding for those bytes.
     */
    private static func base64EncodeBytes(_ bytes: [UInt8], options: Base64EncodingOptions = []) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity((bytes.count/3)*4)
        
        let lineOptions : (lineLength : Int, separator : [UInt8])? = {
            let lineLength: Int
            
            if options.contains(.lineLength64Characters) { lineLength = 64 }
            else if options.contains(.lineLength76Characters) { lineLength = 76 }
            else {
                return nil
            }
            
            var separator = [UInt8]()
            if options.contains(.endLineWithCarriageReturn) { separator.append(13) }
            if options.contains(.endLineWithLineFeed) { separator.append(10) }
            
            //if the kind of line ending to insert is not specified, the default line ending is Carriage Return + Line Feed.
            if separator.isEmpty { separator = [13,10] }
            
            return (lineLength,separator)
        }()
        
        var currentLineCount = 0
        let appendByteToResult : (UInt8) -> Void = {
            result.append($0)
            currentLineCount += 1
            if let options = lineOptions, currentLineCount == options.lineLength {
                result.append(contentsOf: options.separator)
                currentLineCount = 0
            }
        }
        
        var currentByte : UInt8 = 0
        
        for (index,value) in bytes.enumerated() {
            switch index%3 {
            case 0:
                currentByte = (value >> 2)
                appendByteToResult(NSData.base64EncodeByte(currentByte))
                currentByte = ((value << 6) >> 2)
            case 1:
                currentByte |= (value >> 4)
                appendByteToResult(NSData.base64EncodeByte(currentByte))
                currentByte = ((value << 4) >> 2)
            case 2:
                currentByte |= (value >> 6)
                appendByteToResult(NSData.base64EncodeByte(currentByte))
                currentByte = ((value << 2) >> 2)
                appendByteToResult(NSData.base64EncodeByte(currentByte))
            default:
                fatalError()
            }
        }
        //add padding
        switch bytes.count%3 {
        case 0: break //no padding needed
        case 1:
            appendByteToResult(NSData.base64EncodeByte(currentByte))
            appendByteToResult(self.base64Padding)
            appendByteToResult(self.base64Padding)
        case 2:
            appendByteToResult(NSData.base64EncodeByte(currentByte))
            appendByteToResult(self.base64Padding)
        default:
            fatalError()
        }
        return result
    }
    
}

// MARK: -
extension NSData : _CFBridgeable, _SwiftBridgeable {
    typealias SwiftType = Data
    internal var _swiftObject: SwiftType { return Data(referencing: self) }
}

extension Data : _NSBridgeable, _CFBridgeable {
    typealias CFType = CFData
    typealias NSType = NSData
    internal var _cfObject: CFType { return _nsObject._cfObject }
    internal var _nsObject: NSType { return _bridgeToObjectiveC() }
}

extension CFData : _NSBridgeable, _SwiftBridgeable {
    typealias NSType = NSData
    typealias SwiftType = Data
    internal var _nsObject: NSType { return unsafeBitCast(self, to: NSType.self) }
    internal var _swiftObject: SwiftType { return Data(referencing: self._nsObject) }
}

// MARK: -

/// `NSMutableData` and its superclass `NSData` provide data objects, or
/// object-oriented wrappers for byte buffers. Data objects let simple allocated
/// buffers (that is, data with no embedded pointers) take on the behavior of
/// Foundation objects. They are typically used for data storage and are also
/// useful in Distributed Objects applications, where data contained in data
/// objects can be copied or moved between applications. `NSData` creates static
/// data objects, and `NSMutableData` creates dynamic data objects. You can
/// easily convert one type of data object to the other with the initializer
/// that takes an `NSData` object or an `NSMutableData` object as an argument.
///
/// The following `NSData` initializers change when used on a mutable data
/// object:
/// - `init(bytesNoCopy:length:freeWhenDone:)`
/// - `init(bytesNoCopy:length:deallocator:)`
/// - `init(bytesNoCopy:length:)`
///
/// When called, the bytes are immediately copied and then the buffer is freed.
///
/// `NSMutableData` is “toll-free bridged” with its Core Foundation counterpart,
/// `CFMutableData`.
///
/// - Important: The Swift overlay to the Foundation framework provides
///              the `Data` structure, which bridges to the `NSData` class and
///              its mutable subclass, `NSMutableData`. The `Data` value type
///              offers the same functionality as the `NSData` reference type,
///              and the two can be used interchangeably in Swift code that
///              interacts with Objective-C APIs. This behavior is similar to
///              how Swift bridges standard string, numeric, and collection
///              types to their corresponding Foundation classes.
open class NSMutableData : NSData {
    internal var _cfMutableObject: CFMutableData { return unsafeBitCast(self, to: CFMutableData.self) }
    
    // NOTE: the deallocator block here is implicitly @escaping by virtue of it being optional
    public override init(bytes: UnsafeMutableRawPointer?, length: Int, copy: Bool = false, deallocator: (/*@escaping*/ (UnsafeMutableRawPointer, Int) -> Void)? = nil) {
        super.init(bytes: bytes, length: length, copy: copy, deallocator: deallocator)
    }
    public init() {
        self.init(bytes: nil, length: 0)
    }
        
    /// Initializes an `NSMutableData` object capable of holding the specified
    /// number of bytes.
    ///
    /// This method doesn’t necessarily allocate the requested memory right
    /// away. Mutable data objects allocate additional memory as needed, so
    /// capacity simply establishes the object’s initial capacity. When it does
    /// allocate the initial memory, though, it allocates the specified amount.
    /// This method sets the length of the data object to 0.
    ///
    /// If the capacity specified in capacity is greater than four memory pages
    /// in size, this method may round the amount of requested memory up to
    /// the nearest full page.
    ///
    /// The initialized object has the same memory alignment guarantees as
    /// `malloc(_:)`.
    ///
    /// - Parameter capacity: The number of bytes the data object can initially
    ///                       contain.
    public convenience init?(capacity: Int) {
        self.init(bytes: nil, length: 0)
    }
    
    /// Initializes an `NSMutableData` object containing a given number of
    /// zeroed bytes.
    ///
    /// The returned object has the same memory alignment guarantees as
    /// `malloc(_:)`.
    ///
    /// - Parameter length: The number of bytes the object initially contains.
    public convenience init?(length: Int) {
        self.init(bytes: nil, length: 0)
        self.length = length
    }
    
    // MARK: - Funnel Methods
    
    /// A pointer to the data contained by the mutable data object.
    ///
    /// - Note: This property is similar to, but different than the `bytes`
    ///         property. The `bytes` property contains a pointer to a constant.
    ///         You can use the `bytes` pointer to read the data managed by
    ///         the data object, but you cannot modify that data. However,
    ///         the `mutableBytes` property contains a pointer that points
    ///         to mutable data. You can use the `mutableBytes`
    ///         pointer to modify the data managed by the data object.
    open var mutableBytes: UnsafeMutableRawPointer {
        return UnsafeMutableRawPointer(CFDataGetMutableBytePtr(_cfMutableObject))
    }
    
    /// The number of bytes contained by the data object.
    open override var length: Int {
        get {
            return CFDataGetLength(_cfObject)
        }
        set {
            CFDataSetLength(_cfMutableObject, newValue)
        }
    }
    
    // MARK: - NSObject
    
    /// Returns a new `NSData` that’s a copy of the current one.
    ///
    /// - Parameter zone:   This parameter is ignored. Memory zones are no
    ///                     longer used.
    /// - Returns:          A new `NSData` instance that’s a copy of the current
    ///                     one.
    open override func copy(with zone: NSZone? = nil) -> Any {
        return NSData(bytes: bytes, length: length)
    }

    // MARK: - Mutability
    
    /// Appends to the data object a given number of bytes from a given buffer.
    ///
    /// - Parameters:
    ///   - bytes:  A buffer containing data to append to the data object's
    ///             content.
    ///   - length: The number of bytes from `bytes` to append.
    open func append(_ bytes: UnsafeRawPointer, length: Int) {
        let bytePtr = bytes.bindMemory(to: UInt8.self, capacity: length)
        CFDataAppendBytes(_cfMutableObject, bytePtr, length)
    }
    
    /// Appends the content of a `Data` value to the data object.
    ///
    /// - Parameter other: The data value whose content is to be appended to
    ///                    the contents of the instance.
    open func append(_ other: Data) {
        let otherLength = other.count
        other.withUnsafeBytes {
            append($0, length: otherLength)
        }
        
    }
    
    /// Increases the length of the data object by a given number of bytes.
    ///
    /// The additional bytes are all set to `0`.
    ///
    /// - Important: Changing the length of a mutable data object invalidates
    ///              any existing data pointers returned by the `bytes` or
    ///              `mutableBytes` properties.
    ///
    /// - Parameter extraLength: The number of bytes by which to increase
    ///                          the data object's length.
    open func increaseLength(by extraLength: Int) {
        CFDataSetLength(_cfMutableObject, CFDataGetLength(_cfObject) + extraLength)
    }
    
    /// Replaces with a given set of bytes a given range within the contents of
    /// the data object.
    ///
    /// The data object is resized to accommodate the new bytes, if necessary.
    ///
    /// - Parameters:
    ///   - range: The range within the receiver's contents to replace with
    ///            `bytes`. The range must not exceed the bounds of the object.
    ///   - bytes: The data to insert into the object's contents.
    open func replaceBytes(in range: NSRange, withBytes bytes: UnsafeRawPointer) {
        let bytePtr = bytes.bindMemory(to: UInt8.self, capacity: length)
        CFDataReplaceBytes(_cfMutableObject, CFRangeMake(range.location, range.length), bytePtr, length)
    }
    
    /// Replaces with zeroes the contents of the data object in a given range.
    ///
    /// The receiver is resized to accommodate the new bytes, if necessary.
    ///
    /// - Parameter range: The range within the contents of the data object to
    ///                    be replaced by zeros. The range must not exceed
    ///                    the bounds of the object.
    open func resetBytes(in range: NSRange) {
        bzero(mutableBytes.advanced(by: range.location), range.length)
    }
    
    /// Replaces the entire contents of the data object with the contents of
    /// the provided data value.
    ///
    /// As part of its implementation, this method calls
    /// `replaceBytes(in:withBytes:)`.
    ///
    /// - Parameter data: The data value whose content replaces that of
    ///                   the receiver.
    open func setData(_ data: Data) {
        length = data.count
        data.withUnsafeBytes {
            replaceBytes(in: NSMakeRange(0, length), withBytes: $0)
        }
        
    }
    
    /// Replaces with a given set of bytes a given range within the contents
    /// of the data object.
    ///
    /// If the length of `range` is not equal to `replacementLength`,
    /// the data object is resized to accommodate the new bytes. Any bytes past
    /// range in the data object are shifted to accommodate the new bytes. You
    /// can therefore pass `nil` for `replacementBytes` and `0` for
    /// `replacementLength` to delete bytes in the receiver in the range
    /// `range`. You can also replace a range (which might be zero-length) with
    /// more bytes than the length of the range, which has the effect of
    /// insertion (or “replace some and insert more”).
    ///
    /// - Parameters:
    ///   - range:             The range within the data object's contents to
    ///                        replace with `replacementBytes`. The range must
    ///                        not exceed the bounds of the object.
    ///   - replacementBytes:  The data to insert into the data object's
    ///                        contents.
    ///   - replacementLength: The number of bytes to take from
    ///                        `replacementBytes`.
    open func replaceBytes(in range: NSRange, withBytes replacementBytes: UnsafeRawPointer?, length replacementLength: Int) {
        if let replacementBytes = replacementBytes {
            let bytePtr = replacementBytes.bindMemory(to: UInt8.self, capacity: replacementLength)
            CFDataReplaceBytes(_cfMutableObject, CFRangeMake(range.location, range.length), bytePtr, replacementLength)
        }
    }
}

extension NSData : _StructTypeBridgeable {
    public typealias _StructType = Data
    public func _bridgeToSwift() -> Data {
        return Data._unconditionallyBridgeFromObjectiveC(self)
    }
}
