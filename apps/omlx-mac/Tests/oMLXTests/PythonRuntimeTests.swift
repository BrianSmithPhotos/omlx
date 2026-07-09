// Coverage for the dev-checkout fallback in PythonRuntime.resolve().
//
// The bug this guards against: running the app straight from Xcode (⌘R)
// against a git checkout — rather than a packaged .app built via
// apps/omlx-mac/Scripts/build.sh — has no embedded venvstacks Python, so
// resolve() used to throw ResolutionError.notFound with no way to start the
// server short of manually setting OMLX_PYTHON_OVERRIDE every time. resolve()
// now falls back to `<repo>/.venv/bin/python3` (the uv-managed dev venv)
// when nothing else matches, located via the build-time path of
// PythonRuntime.swift itself — which is exactly the situation an xctest run
// in this checkout exercises for free.

import Foundation
import XCTest
@testable import oMLX

final class PythonRuntimeTests: XCTestCase {

    func testResolveFallsBackToDevCheckoutVenv() throws {
        guard ProcessInfo.processInfo.environment["OMLX_PYTHON_OVERRIDE"] == nil else {
            throw XCTSkip(
                "OMLX_PYTHON_OVERRIDE is set in this environment, so it wins " +
                "before the dev-checkout fallback is ever reached."
            )
        }

        let runtime = try PythonRuntime.resolve()

        XCTAssertFalse(
            runtime.isBundled,
            "No venvstacks Python is embedded in an Xcode debug build; this must resolve to the dev checkout's .venv, not a bundled runtime."
        )
        XCTAssertTrue(
            runtime.executable.path.hasSuffix(".venv/bin/python3"),
            "Expected the repo's uv-managed venv, got \(runtime.executable.path)"
        )
        XCTAssertTrue(
            FileManager.default.isExecutableFile(atPath: runtime.executable.path),
            "\(runtime.executable.path) must actually be executable, not just a plausible-looking path"
        )
    }
}
