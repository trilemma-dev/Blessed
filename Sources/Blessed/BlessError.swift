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
        
        let toolAssessor = HelperToolAssessor(label: label)
        let appAssessor = AppAssessor()
        self.assessments = [
            appAssessor.isSigned(), // 1
            toolAssessor.isExecutable(), // 2 & 3
            toolAssessor.isSigned(), // 4
            toolAssessor.launchdPropertyList(), // 5 & 6
            toolAssessor.infoPropertyListAuthorizedClients(type: .bundled), // 7 & 8 - bundled
            toolAssessor.infoPropertyListAuthorizedClients(type: .installed), // 7 & 8 - bundled
            toolAssessor.infoPropertyListBundleVersion(), // 9
            appAssessor.infoPropertyList(bundledHelperToolLocation: toolAssessor.bundledLocation, label: label) // 10
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


// The numbers in front of each function corresponds to the requirements described in LaunchdManager.bless(...)


fileprivate struct HelperToolAssessor {
    
    enum HelperToolType: String {
        case bundled
        case installed
    }
    
    let label: String
    
    var bundledLocation: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents")
                             .appendingPathComponent("Library")
                             .appendingPathComponent("LaunchServices")
                             .appendingPathComponent(label)
    }

    var installedLocation: URL {
        URL(fileURLWithPath: "/Library/PrivilegedHelperTools/\(label)")
    }
    
    // 2 & 3
    fileprivate func isExecutable() -> Assessment {
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: bundledLocation.path, isDirectory: &isDirectory) else {
            return .notSatisfied(explanation: """
            There is no bundled helper tool in this application's /Contents/Library/LaunchServices/ directory with the \
            file name: \(label)
            """)
        }
        if isDirectory.boolValue {
            return .notSatisfied(explanation: """
            The bundled helper tool must be a file, not a directory (such as an .app bundle).
            """)
        }
        
        // Now determine if this file is a Mach-O executable by looking at the first four bytes for the "magic" value.
        // There are six valid "magic" values: 32-bit, 64-bit, and fat (universal) binaries — in either endianess.
        guard let toolData = try? Data(contentsOf: bundledLocation) else {
            return .notDetermined(explanation: "Unable to read contents of the bundled helper tool.")
        }
        let firstFourBytes = toolData.withUnsafeBytes { pointer in
            pointer.load(fromByteOffset: 0, as: UInt32.self)
        }
        let validMagicValues: Set<UInt32> = [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM]
        guard validMagicValues.contains(firstFourBytes) else {
            return .notSatisfied(explanation: "The bundle helper tool is not a Mach-O executable.")
        }
        
        return .satisfied
    }
    
    // 4
    fileprivate func isSigned() -> Assessment {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundledLocation as CFURL, [], &code) == errSecSuccess, let code = code else {
            return .notDetermined(explanation: "Could not create SecStaticCode for bundled helper tool.")
        }
        
        let result = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
        switch result {
            case errSecSuccess:
                return .satisfied
            case errSecCSUnsigned:
                return .notSatisfied(explanation: "The bundled helper tool does not have a valid signature.")
            default:
                return .notDetermined(explanation: """
                Signature checking failed.
                Error: \(result)
                """)
        }
    }

    // 5 & 6
    fileprivate func launchdPropertyList() -> Assessment {
        let data: Data
        do {
            data = try EmbeddedPropertyListReader.launchd.readExternal(from: bundledLocation)
        } catch ReadError.sectionNotFound {
            return .notSatisfied(explanation: """
            The bundled helper tool does not have an embedded launchd property list.
            """)
        } catch {
            return .notDetermined(explanation: """
            Failed trying to read the bundled helper tool's embedded launchd property list.
            Error: \(error)
            """)
        }
        
        // The helper tool's embedded launchd property list **must** have an entry with `Label` as the key and the
        // value **must** be the filename of the helper tool.
        guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                     options: .mutableContainersAndLeaves,
                                                                     format: nil) as? NSDictionary else {
            return .notSatisfied(explanation: """
            The data embedded as the bundled helper tool's launchd property list is not a valid property list.
            """)
        }
        guard let plistLabel = plist["Label"] else {
            return .notSatisfied(explanation: """
            The bundled helper tool's embedded launchd property list does not have a Label key.
            """)
        }
        guard label == plistLabel as? String else {
            return .notSatisfied(explanation:
            """
            The bundled helper tool's launchd property list's value for the Label key does not match the label for the \
            bundled helper tool.
            Required value: \(label)
            Actual value: \(plistLabel)
            """)
        }
        
        return .satisfied
    }
    
    // 7 & 8
    fileprivate func infoPropertyListAuthorizedClients(type: HelperToolType) -> Assessment {
        let toolURL: URL
        switch type {
            case .bundled:
                toolURL = bundledLocation
            case .installed:
                toolURL = installedLocation
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
            return .notSatisfied(explanation: "The \(type.rawValue) helper tool does not have an info property list.")
        } catch {
            return .notDetermined(explanation: """
            Failed trying to read the \(type.rawValue) helper tool's info property list.
            Error: \(error)
            """)
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                      options: .mutableContainersAndLeaves,
                                                                      format: nil) as? NSDictionary else {
            return .notSatisfied(explanation: """
            The data embedded as the \(type.rawValue) helper tool's info property list is not a valid property list.
            """)
        }
        
        // The helper tool's embedded info property list **must** have an entry with SMAuthorizedClients as its key
        guard let clients = plist["SMAuthorizedClients"] else {
            return .notSatisfied(explanation: """
            The \(type.rawValue) helper tool's info property list does not have a SMAuthorizedClients key.
            """)
        }
        
        // Its value **must** be an array of strings
        guard let clients = clients as? [String] else {
            return .notSatisfied(explanation: """
            The \(type.rawValue) helper tool's info property list's value for SMAuthorizedClients is not an array of \
            strings.
            """)
        }
        
        // Each string **must** be a code signing requirement
        var clientRequirements = [SecRequirement]()
        var invalidRequirementStrings = [String]()
        for client in clients {
            var requirement: SecRequirement?
            if SecRequirementCreateWithString(client as CFString, [], &requirement) == errSecSuccess,
               let requirement = requirement {
                clientRequirements.append(requirement)
            } else {
                invalidRequirementStrings.append(client)
            }
        }
        guard invalidRequirementStrings.isEmpty else {
            return .notSatisfied(explanation: """
            The \(type.rawValue) helper tool's embedded info property list's value for SMAuthorizedClients contains \
            one or more strings which are not valid requirements:
            \(invalidRequirementStrings.joined(separator: "\n"))
            """)
        }
        
        // The app **must** satisify at least one of these requirements
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
            return .notDetermined(explanation: "Could not create SecCode for this application.")
        }
        
        let metRequirements = clientRequirements.contains { SecCodeCheckValidity(code, [], $0) == errSecSuccess }
        guard metRequirements else {
            let intro = """
            This application did not meet any of the \(type.rawValue) helper tool's code signing requirements:
            """
            let explanation = clientRequirements.reduce(into: intro) { explanation, requirement in
                let eval = try? (try? Parser.parse(requirement: requirement))?.evaluateForCode(code)
                explanation += "\n\(eval?.prettyDescription ?? "Failed to evaluate requirement.")"
            }
            
            return .notSatisfied(explanation: explanation)
        }
        
        return .satisfied
    }
    
    // 9
    fileprivate func infoPropertyListBundleVersion() -> Assessment {
        let data: Data
        do {
            data = try EmbeddedPropertyListReader.info.readExternal(from: bundledLocation)
        } catch ReadError.sectionNotFound {
            return .notSatisfied(explanation: "The bundled helper tool does not have an info property list.")
        } catch {
            return .notDetermined(explanation: """
            Failed trying to read the bundled helper tool's info property list.
            Error: \(error)
            """)
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                      options: .mutableContainersAndLeaves,
                                                                      format: nil) as? NSDictionary else {
            return .notSatisfied(explanation: """
            The data embedded as the bundled helper tool's info property list is not a valid property list.
            """)
        }
        
        // The helper tool's embedded info property list **must** have an entry with CFBundleVersion as its key
        guard let bundledBundleVersion = plist["CFBundleVersion"] else {
            return .notSatisfied(explanation: """
            The bundled helper tool's info property list does not have a CFBundleVersion key.
            """)
        }
        // CFBundleVersion must be a string
        guard let bundledBundleVersion = bundledBundleVersion as? String else {
            return .notSatisfied(explanation: """
            The bundled helper tool's info property list's value for CFBundleVersion is not a string."
            """)
        }
        // The value for CFBundleVersion must conform to its documentation
        guard let bundledBundleVersion = BundleVersion(rawValue: bundledBundleVersion) else {
            return .notSatisfied(explanation: """
            The bundled helper tool's info property list's value for CFBundleVersion does not conform to the \
            documented requirements.
            Value: \(bundledBundleVersion)
            See https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion
            """)
        }
        
        // If a helper tool is installed, the bundled bundle version must be greater than the installed bundle version
        if FileManager.default.fileExists(atPath: installedLocation.path) {
            // The installed helper tool ought to have a info property list with a valid CFBundleVersion or it shouldn't
            // have been installable in the first place; however, the following doesn't assume that's the case
            let data: Data
            do {
                data = try EmbeddedPropertyListReader.info.readExternal(from: installedLocation)
            } catch ReadError.sectionNotFound {
                return .notSatisfied(explanation: "The installed helper tool does not have an info property list.")
            } catch {
                return .notDetermined(explanation: """
                Failed trying to read the installed helper tool's info property list.
                Error: \(error)
                """)
            }
            guard let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                          options: .mutableContainersAndLeaves,
                                                                          format: nil) as? NSDictionary else {
                return .notSatisfied(explanation: """
                The data embedded as the installed helper tool's info property list is not a valid property list
                """)
            }
            guard let installedBundleVersion = plist["CFBundleVersion"] as? String else {
                return .notSatisfied(explanation: """
                The installed helper tool's info property list does not have a CFBundleVersion entry.
                """)
            }
            guard let installedBundleVersion = BundleVersion(rawValue: installedBundleVersion) else {
                return .notSatisfied(explanation: """
                The installer helper tool's info property list's value for CFBundleVersion does not conform to the \
                documented requirements.
                Value: \(installedBundleVersion)
                See https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion
                """)
            }
            
            guard bundledBundleVersion > installedBundleVersion else {
                return .notSatisfied(explanation: """
                The bundled helper tool does not have a greater CFBundleVersion value than the installed helper tool \
                with the label: \(label)
                Bundled version: \(bundledBundleVersion.rawValue)
                Installed version: \(installedBundleVersion.rawValue)
                """)
            }
        }
        
        return .satisfied
    }
}

fileprivate struct AppAssessor {
    // 1
    fileprivate func isSigned() -> Assessment {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
            return .notDetermined(explanation: "Could not create SecCode for this application.")
        }
        
        let result = SecCodeCheckValidity(code, [], nil)
        switch result {
            case errSecSuccess:
                return .satisfied
            case errSecCSUnsigned:
                return .notSatisfied(explanation: "This application does not have a valid signature.")
            default:
                return .notDetermined(explanation: """
                Signature checking failed.
                Error: \(result)
                """)
        }
    }

    // 10
    fileprivate func infoPropertyList(bundledHelperToolLocation: URL, label: String) -> Assessment {
        guard let infoDictionary = Bundle.main.infoDictionary else {
            return .notSatisfied(explanation: "This application does not have an info property list.")
        }
        
        // The app's info property list **must** have an entry with SMPrivilegedExecutables as its key
        guard let privilegedExecutables = infoDictionary["SMPrivilegedExecutables"] else {
            return .notSatisfied(explanation: """
            This application's info property list does not have a SMPrivilegedExecutables key.
            """)
        }
        
        // Its value **must** be a dictionary of strings to strings
        guard let privilegedExecutables = privilegedExecutables as? [String : String] else {
            return .notSatisfied(explanation: """
            This application's info property list's value for SMPrivilegedExecutables is not a dictionary of strings \
            to strings.
            """)
        }
        
        // There must be an entry for the specified helper tool
        guard let requirementString = privilegedExecutables[label] else {
            return .notSatisfied(explanation: """
            This application's info property list's value for SMPrivilegedExecutables does not contain a key for the \
            label: \(label)
            """)
        }
        
        // If the SecRequirement can't be created (compiled), then it's not valid
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementString as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement else {
            return .notSatisfied(explanation: """
            This application's code signing requirement for the helper tool is not valid. This is independent of \
            whether the helper tool satisifies the code signing requirement.
            Invalid requirement: \(requirementString)
            """)
        }
        
        // Get the bundled tool and see if it satisfies this requirement
        var bundledStaticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundledHelperToolLocation as CFURL, [], &bundledStaticCode) == errSecSuccess,
              let bundledStaticCode = bundledStaticCode else {
            return .notDetermined(explanation: "Could not create SecStaticCode for bundled helper tool.")
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        let result = SecStaticCodeCheckValidity(bundledStaticCode, flags, requirement)
        switch result {
            case errSecSuccess:
                return .satisfied
            case errSecCSReqFailed:
                let eval = try? (try? Parser.parse(requirement: requirement))?.evaluateForStaticCode(bundledStaticCode)
                
                return .notSatisfied(explanation: """
                The bundled helper tool does not meet the application's code signing requirement for it:
                \(eval?.prettyDescription ?? "Failed to evaluate requirement: \(requirementString)")
                """)
            default:
                return .notDetermined(explanation: """
                Signature checking failed.
                Error: \(result)
                """)
        }
    }
}
