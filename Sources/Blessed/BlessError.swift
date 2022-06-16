//
//  BlessError.swift
//  Blessed
//
//  Created by Josh Kaplan on 2022-06-10
//

import Foundation
import EmbeddedPropertyList
import Required

/// An error thrown when ``LaunchdManager/bless(label:authorization:)`` fails.
///
/// ## Topics
/// ### Error Info
/// - ``description``
/// - ``underlyingError``
public struct BlessError: Error {
    private let assessments: [Assessment]
    
    /// The original error, if present, provided by the Service Management framework.
    public let underlyingError: CFError?
    
    init(underlyingError: CFError?, label: String, authorization: Authorization) {
        self.underlyingError = underlyingError
        self.assessments = [
            assessAppIsSigned(), // 1
            assessHelperToolIsExecutable(label: label), // 2 & 3
            assessHelperToolIsSigned(label: label), // 4
            asssessHelperToolLaunchdPropertyList(label: label), // 5 & 6
            asssessHelperToolInfoPropertyListAuthorizedClients(label: label, type: .bundled), // 7 & 8 - bundled
            asssessHelperToolInfoPropertyListAuthorizedClients(label: label, type: .installed), // 7 & 8 - installed
            asssessHelperToolInfoPropertyListBundleVersion(label: label), // 9
            asssessAppInfoPropertyList(label: label) // 10
        ]
    }
}

// MARK: description

extension BlessError: CustomStringConvertible {
    /// A detailed description of why `bless` failed.
    public var description: String {
        let notSatisfiedAssessments = assessments.compactMap { (assessment: Assessment) -> String? in
            switch assessment {
                case .notSatisfied(let explanation):    return explanation
                default:                                return nil
            }
        }
        let notDeterminedAssessments = assessments.compactMap { (assessment: Assessment) -> String? in
            switch assessment {
                case .notDetermined(let explanation):   return explanation
                default:                                return nil
            }
        }
        
        var message = "[BlessError] "
        if !notSatisfiedAssessments.isEmpty {
            if notSatisfiedAssessments.count == 1, let assessment = notSatisfiedAssessments.first {
                message += assessment
            } else {
                message += "\(notSatisfiedAssessments.count) bless requirements were not met:\n"
                message += notSatisfiedAssessments.enumerated().map { (index, assessment) in
                    // Prefix each line of the assessment with a tab, then prefix the entire assessment with the index
                    let assessment = assessment.split(separator: "\n").map{ "\t\($0)" }.joined(separator: "\n")
                    return "\(index + 1). \(assessment)"
                }.joined(separator: "\n")
            }
        } else if !notDeterminedAssessments.isEmpty {
            if notDeterminedAssessments.count == 1, let assessment = notDeterminedAssessments.first {
                message += "Bless failed and the following requirement could not be determined:\n"
                message += assessment
            } else {
                message += "Bless failed and \(notDeterminedAssessments.count) requirements could not be determined:\n"
                message += notDeterminedAssessments.enumerated().map { (index, assessment) in
                    // Prefix each line of the assessment with a tab, then prefix the entire assessment with the index
                    let assessment = assessment.split(separator: "\n").map{ "\t\($0)" }.joined(separator: "\n")
                    return "\(index + 1). \(assessment)"
                }.joined(separator: "\n")
            }
        } else { // TODO: handle some of the specific values for underlyingError to reduce this happening
            message += "Bless failed, but no specific unmet requirements were determined."
        }
        
        if let underlyingError = underlyingError {
            message += "\nUnderlying error: \(underlyingError)"
        }
            
        return message
    }
}

// MARK: Assessment of bless requirements

private enum Assessment {
    case satisfied
    case notSatisfied(explanation: String)
    case notDetermined(explanation: String)
}

private enum HelperToolType: String {
    case bundled
    case installed
}

// The numbers in front of each function correspond to the requirements described in LaunchdManager.bless(...)

// 1
fileprivate func assessAppIsSigned() -> Assessment {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
        return .notDetermined(explanation: "Could not create SecCode for this application")
    }
    
    let result = SecCodeCheckValidity(code, [], nil)
    if result == errSecSuccess {
        return .satisfied
    } else if result == errSecCSUnsigned {
        return .notSatisfied(explanation: "This application does not have a valid signature")
    } else {
        return .notDetermined(explanation: "Signature checking failed with error \(result)")
    }
}

// 2 & 3
fileprivate func assessHelperToolIsExecutable(label: String) -> Assessment {
    let toolURL = bundledHelperToolLocation(label: label)
    
    var isDirectory = ObjCBool(false)
    guard FileManager.default.fileExists(atPath: toolURL.path, isDirectory: &isDirectory) else {
        return .notSatisfied(explanation: "There is no bundled helper tool in this application's " +
                                          "/Contents/Library/LaunchServices/ directory with the file name: \(label)")
    }
    if isDirectory.boolValue {
        return .notSatisfied(explanation: "The bundled helper tool must be a file, not a directory (such as an " +
                                          ".app bundle)")
    }
    
    // Now determine if this file is a Mach-O executable by looking at the first four bytes for the "magic" value.
    // There are six valid "magic" values: 32-bit, 64-bit, and fat (universal) binaries — in either endianess.
    guard let toolData = try? Data(contentsOf: toolURL) else {
        return .notDetermined(explanation: "Unable to read contents of the bundled helper tool")
    }
    let firstFourBytes = toolData.withUnsafeBytes { pointer in
        pointer.load(fromByteOffset: 0, as: UInt32.self)
    }
    let validMagicValues: Set<UInt32> = [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM]
    guard validMagicValues.contains(firstFourBytes) else {
        return .notSatisfied(explanation: "The bundle helper tool is not a Mach-O executable")
    }
    
    return .satisfied
}

// 4
fileprivate func assessHelperToolIsSigned(label: String) -> Assessment {
    let toolURL = bundledHelperToolLocation(label: label)
    
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(toolURL as CFURL, [], &code) == errSecSuccess, let code = code else {
        return .notDetermined(explanation: "Could not create SecStaticCode for bundled helper tool")
    }
    
    let result = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
    if result == errSecSuccess {
        return .satisfied
    } else if result == errSecCSUnsigned {
        return .notSatisfied(explanation: "The bundled helper tool does not have a valid signature")
    } else {
        return .notDetermined(explanation: "Signature checking failed with error \(result)")
    }
}

// 5 & 6
fileprivate func asssessHelperToolLaunchdPropertyList(label: String) -> Assessment {
    let toolURL = bundledHelperToolLocation(label: label)
    let data: Data
    do {
        data = try EmbeddedPropertyListReader.launchd.readExternal(from: toolURL)
    } catch ReadError.sectionNotFound {
        return .notSatisfied(explanation: "The bundled helper tool does not have an embedded launchd property list")
    } catch {
        return .notDetermined(explanation: "Failed trying to read the bundled helper tool's embedded launchd " +
                                           "property list \(error)")
    }
    
    // The helper tool's embedded launchd property list **must** have an entry with `Label` as the key and the
    // value **must** be the filename of the helper tool.
    guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                 options: .mutableContainersAndLeaves,
                                                                 format: nil) as? NSDictionary else {
        return .notSatisfied(explanation: "The data embedded as the bundled helper tool's launchd property list is " +
                                          "not a valid property list")
    }
    guard let plistLabel = plist["Label"] else {
        return .notSatisfied(explanation: "The bundled helper tool's embedded launchd property list does not have a " +
                                          "Label key")
    }
    guard label == plistLabel as? String else {
        return .notSatisfied(explanation: "The bundled helper tool's launchd property list's value for the Label key " +
                                           "does not match the label for the bundled helper tool\n" +
                                           "Required value: \(label)\n" +
                                           "Actual value: \(plistLabel)")
    }
    
    return .satisfied
}

// 7 & 8
fileprivate func asssessHelperToolInfoPropertyListAuthorizedClients(label: String, type: HelperToolType) -> Assessment {
    let toolURL: URL
    switch type {
        case .bundled:
            toolURL = bundledHelperToolLocation(label: label)
        case .installed:
            toolURL = installedHelperToolLocation(label: label)
            // If the helper tool isn't installed, there's nothing to check here
            guard FileManager.default.fileExists(atPath: toolURL.path) else {
                return .satisfied
            }
    }
    
    // The helper tool **must** have an embedded info property list
    let data: Data
    do {
        data = try EmbeddedPropertyListReader.info.readExternal(from: toolURL)
    } catch ReadError.sectionNotFound {
        return .notSatisfied(explanation: "The \(type.rawValue) helper tool does not have an info property list")
    } catch {
        return .notDetermined(explanation: "Failed trying to read the \(type.rawValue) helper tool's info property " +
                                           "list. Error: \(error)")
    }
    guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                  options: .mutableContainersAndLeaves,
                                                                  format: nil) as? NSDictionary else {
        return .notSatisfied(explanation: "The data embedded as the \(type.rawValue) helper tool's info property " +
                                          "list is not a valid property list")
    }
    
    // The helper tool's embedded info property list **must** have an entry with SMAuthorizedClients as its key
    guard let authorizedClients = plist["SMAuthorizedClients"] else {
        return .notSatisfied(explanation: "The \(type.rawValue) helper tool's info property list does not have a " +
                                          "SMAuthorizedClients key")
    }
    
    // Its value **must** be an array of strings
    guard let authorizedClients = authorizedClients as? [String] else {
        return .notSatisfied(explanation: "The \(type.rawValue) helper tool's info property list's value for " +
                                          "SMAuthorizedClients is not an array of strings")
    }
    
    // Each string **must** be a code signing requirement
    var authorizedClientRequirements = [SecRequirement]()
    var invalidRequirementStrings = [String]()
    for authorizedClient in authorizedClients {
        var requirement: SecRequirement?
        if SecRequirementCreateWithString(authorizedClient as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement {
            authorizedClientRequirements.append(requirement)
        } else {
            invalidRequirementStrings.append(authorizedClient)
        }
    }
    guard invalidRequirementStrings.isEmpty else {
        var explanation = "The \(type.rawValue) helper tool's embedded info property list's value for " +
                          "SMAuthorizedClients contains one or more strings which are not valid requirements:\n"
        explanation += invalidRequirementStrings.joined(separator: "\n")
        return .notSatisfied(explanation: explanation)
    }
    
    // The app **must** satisify at least one of these requirements
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
        return .notDetermined(explanation: "Could not create SecCode for this application")
    }
    
    let metRequirements = authorizedClientRequirements.contains { SecCodeCheckValidity(code, [], $0) == errSecSuccess }
    guard metRequirements else {
        var explanation = "This application did not meet any of the \(type.rawValue) helper tool's requirements:"
        for requirement in authorizedClientRequirements {
            let evaluation = try? (try? Parser.parse(requirement: requirement))?.evaluateForCode(code)
            explanation += "\n\(evaluation?.prettyDescription ?? "Failed to evaluate requirement.")"
        }
        return .notSatisfied(explanation: explanation)
    }
    
    return .satisfied
}

// 9
fileprivate func asssessHelperToolInfoPropertyListBundleVersion(label: String) -> Assessment {
    let bundledToolURL = bundledHelperToolLocation(label: label)
    
    let data: Data
    do {
        data = try EmbeddedPropertyListReader.info.readExternal(from: bundledToolURL)
    } catch ReadError.sectionNotFound {
        return .notSatisfied(explanation: "The bundled helper tool does not have an info property list")
    } catch {
        return .notDetermined(explanation: "Failed trying to read the bundled helper tool's info property list. " +
                                           "Error: \(error)")
    }
    guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                  options: .mutableContainersAndLeaves,
                                                                  format: nil) as? NSDictionary else {
        return .notSatisfied(explanation: "The data embedded as the bundled helper tool's info property list is not " +
                                          "a valid property list")
    }
    
    // The helper tool's embedded info property list **must** have an entry with CFBundleVersion as its key
    guard let bundledBundleVersion = plist["CFBundleVersion"] else {
        return .notSatisfied(explanation: "The bundled helper tool's info property list does not have a " +
                                          "CFBundleVersion key")
    }
    // CFBundleVersion must be a string
    guard let bundledBundleVersion = bundledBundleVersion as? String else {
        return .notSatisfied(explanation: "The bundled helper tool's info property list's value for CFBundleVersion " +
                                          "is not a string")
    }
    // The value for CFBundleVersion must conform to its documentation
    guard let bundledBundleVersion = BundleVersion(rawValue: bundledBundleVersion) else {
        return .notSatisfied(explanation: "The bundled helper tool's info property list's value for CFBundleVersion " +
                                          "does not conform to the documented requirements.\n" +
                                          "Value: \(bundledBundleVersion)\n" +
        "See https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion")
    }
    
    // If a helper tool is installed, the bundled bundle version must be greater than the installed bundle version
    let installedHelperToolURL = installedHelperToolLocation(label: label)
    if FileManager.default.fileExists(atPath: installedHelperToolURL.path) {
        // The installed helper tool ought to have a info property list with a valid CFBundleVersion or it shouldn't
        // have been installable in the first place; however, the following doesn't assume that's the case
        let data: Data
        do {
            data = try EmbeddedPropertyListReader.info.readExternal(from: installedHelperToolURL)
        } catch ReadError.sectionNotFound {
            return .notSatisfied(explanation: "The installed helper tool does not have an info property list")
        } catch {
            return .notDetermined(explanation: "Failed trying to read the installed helper tool's info property list. " +
                                               "Error: \(error)")
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                      options: .mutableContainersAndLeaves,
                                                                      format: nil) as? NSDictionary else {
            return .notSatisfied(explanation: "The data embedded as the installed helper tool's info property list " +
                                              "is not a valid property list")
        }
        guard let installedBundleVersion = plist["CFBundleVersion"] as? String else {
            return .notSatisfied(explanation: "The installed helper tool's info property list does not have a " +
                                              "CFBundleVersion entry")
        }
        guard let installedBundleVersion = BundleVersion(rawValue: installedBundleVersion) else {
              return .notSatisfied(explanation: "The installed helper tool's info property list does not have a " +
                                                "valid CFBundleVersion entry. Value: \(installedBundleVersion)")
        }
        
        guard bundledBundleVersion > installedBundleVersion else {
            return .notSatisfied(explanation: "The bundled helper tool does not have a greater CFBundleVersion value " +
                                              "than the installed helper tool with the label: \(label)\n" +
                                              "Bundled: \(bundledBundleVersion.rawValue)\n" +
                                              "Installed: \(installedBundleVersion.rawValue)")
        }
    }
    
    return .satisfied
}

// 10
fileprivate func asssessAppInfoPropertyList(label: String) -> Assessment {
    guard let infoDictionary = Bundle.main.infoDictionary else {
        return .notSatisfied(explanation: "This application does not have an Info.plist")
    }
    
    // The app's info property list **must** have an entry with SMPrivilegedExecutables as its key
    guard let privilegedExecutables = infoDictionary["SMPrivilegedExecutables"] else {
        return .notSatisfied(explanation: "This application's info property list does not have a " +
                                          "SMPrivilegedExecutables key")
    }
    
    // Its value **must** be a dictionary of strings to strings
    guard let privilegedExecutables = privilegedExecutables as? [String : String] else {
        return .notSatisfied(explanation: "This application's info property list's value for SMPrivilegedExecutables " +
                                          "is not a dictionary of strings to strings")
    }
    
    // There must be an entry for the specified helper tool
    guard let requirementString = privilegedExecutables[label] else {
        return .notSatisfied(explanation: "This application's info property list's value for SMPrivilegedExecutables " +
                                          "does not contain a key for the label: \(label)")
    }
    
    // If the SecRequirement can't be created (compiled), then it's not valid
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(requirementString as CFString, [], &requirement) == errSecSuccess,
          let requirement = requirement else {
        return .notSatisfied(explanation: "This application's code signing requirement for the helper tool is not " +
                                          "valid. This is independent of whether the helper tool satisifies the code " +
                                          "signing requirement.\n" +
                                          "Invalid requirement: \(requirementString)")
    }
    
    // Get the bundled tool and see if it satisfies this requirement
    let bundledToolURL = bundledHelperToolLocation(label: label)
    var bundledStaticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(bundledToolURL as CFURL, [], &bundledStaticCode) == errSecSuccess,
          let bundledStaticCode = bundledStaticCode else {
        return .notDetermined(explanation: "Could not create SecStaticCode for bundled helper tool")
    }
    let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
    let result = SecStaticCodeCheckValidity(bundledStaticCode, flags, requirement)
    if result == errSecSuccess {
        return .satisfied
    } else if result == errSecCSReqFailed {
        let evaluation = try? (try? Parser.parse(requirement: requirement))?.evaluateForStaticCode(bundledStaticCode)
        let explanation = "The bundled helper tool does not meet the application's code signing requirement for it:\n" +
                          "\(evaluation?.prettyDescription ?? "Failed to evaluate requirement.")"
        
        return .notSatisfied(explanation: explanation)
    }else {
        return .notDetermined(explanation: "Signature checking failed with error \(result)")
    }
}

// MARK: Helper functions

fileprivate func bundledHelperToolLocation(label: String) -> URL {
    Bundle.main.bundleURL.appendingPathComponent("Contents")
                         .appendingPathComponent("Library")
                         .appendingPathComponent("LaunchServices")
                         .appendingPathComponent(label)
}

fileprivate func installedHelperToolLocation(label: String) -> URL {
    URL(fileURLWithPath: "/Library/PrivilegedHelperTools/\(label)")
}
