// Coverage for the auto-update signature verification gate (jundot/omlx#930).
//
// Before the fix, `mountDMG()` passed `hdiutil attach -noverify` (skipping
// the DMG's own checksum verification) and `performSwapAndRelaunch()`
// stripped the quarantine xattr before opening the swapped-in bundle so an
// unattended relaunch wouldn't hit Gatekeeper's "unidentified developer"
// prompt. Stripping quarantine also means Gatekeeper's own signature check
// never runs for that launch — so a MITM'd DMG or a substituted release
// asset would install and execute with no integrity check at all.
//
// The fix adds an explicit `AppUpdater.verifyStagedSignature(_:against:)`
// gate (codesign --verify + Team ID match against the running app) that
// must pass before a staged update is allowed to become `onReady()`. These
// tests exercise that gate and its `teamIdentifier(of:)` helper directly
// against real signed bundles already present on disk, since AppUpdater's
// staging flow needs live networking/hdiutil and isn't practical to drive
// end-to-end in a unit test.

import Foundation
import XCTest
@testable import oMLX

final class AppUpdaterTests: XCTestCase {

    /// A system app that's actually signed with a real Developer ID Team ID.
    /// Most `/System/Applications/*.app` bundles are Apple-platform-signed
    /// with `TeamIdentifier=not set`, so we use Xcode.app (present in this
    /// environment) as a stable fixture with a non-nil Team ID.
    private let teamSignedApp = URL(fileURLWithPath: "/Applications/Xcode.app")

    /// A system app signed without a Team ID — exercises the "not set" path.
    private let noTeamApp = URL(fileURLWithPath: "/System/Applications/Calculator.app")

    // MARK: - teamIdentifier

    func testTeamIdentifierExtractsRealTeamID() throws {
        guard FileManager.default.fileExists(atPath: teamSignedApp.path) else {
            throw XCTSkip("Xcode.app not present in this environment")
        }
        let teamID = try AppUpdater.teamIdentifier(of: teamSignedApp)
        XCTAssertEqual(teamID, "59GAB85EFG")
    }

    func testTeamIdentifierReturnsNilWhenNotSet() throws {
        guard FileManager.default.fileExists(atPath: noTeamApp.path) else {
            throw XCTSkip("Calculator.app not present in this environment")
        }
        let teamID = try AppUpdater.teamIdentifier(of: noTeamApp)
        XCTAssertNil(teamID)
    }

    // MARK: - verifyStagedSignature

    func testVerifyStagedSignatureAcceptsMatchingTeamID() throws {
        guard FileManager.default.fileExists(atPath: teamSignedApp.path) else {
            throw XCTSkip("Xcode.app not present in this environment")
        }
        // Same bundle on both sides: identical Team ID, must not throw.
        XCTAssertNoThrow(
            try AppUpdater.verifyStagedSignature(teamSignedApp, against: teamSignedApp)
        )
    }

    func testVerifyStagedSignatureRejectsMismatchedTeamID() throws {
        guard FileManager.default.fileExists(atPath: teamSignedApp.path),
              FileManager.default.fileExists(atPath: noTeamApp.path)
        else {
            throw XCTSkip("Fixture apps not present in this environment")
        }
        // "Running app" has no Team ID at all — nothing trustworthy to
        // compare against, so this must fail closed rather than accept
        // any validly-signed update.
        XCTAssertThrowsError(
            try AppUpdater.verifyStagedSignature(teamSignedApp, against: noTeamApp)
        ) { error in
            guard case AppUpdater.UpdateError.signatureVerificationFailed = error else {
                return XCTFail("Expected signatureVerificationFailed, got \(error)")
            }
        }
    }

    func testVerifyStagedSignatureRejectsUnsignedOrMissingBundle() {
        let missing = URL(fileURLWithPath: "/tmp/does-not-exist-\(UUID().uuidString).app")
        XCTAssertThrowsError(
            try AppUpdater.verifyStagedSignature(missing, against: missing)
        ) { error in
            guard case AppUpdater.UpdateError.signatureVerificationFailed = error else {
                return XCTFail("Expected signatureVerificationFailed, got \(error)")
            }
        }
    }
}
