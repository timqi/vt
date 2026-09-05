// VT.app menu-bar shell (docs/app-bundle.md §6).
//
// Roles:
//  - menu-bar UI: agent status, live grants (via the token-gated
//    `ui-status@vt` channel), revoke-all, start/stop of the managed agent;
//  - agent supervisor: spawns `vt ssh agent --ui-token-fd 0` with a random
//    32-byte token written to the child's stdin pipe (never env/argv/file);
//  - `VT notify --title T --body B` helper mode: posts a native
//    UNUserNotificationCenter notification carrying the bundle identity,
//    used by the Rust agent's notify path, then exits.
//
// Security stance: this UI holds no VT_AUTH and can only read status or
// reduce authority (revoke). It never approves anything — Touch ID sheets
// remain the only approval surface. A CLI-started agent (no token) yields a
// degraded read-only view.

import AppKit
import Foundation
import ServiceManagement
import UserNotifications

// MARK: - Wire types (mirror src/core.rs UiStatusReq/UiStatusRes)

struct UiStatusReq: Codable {
    var token: String
    var action: String
}

struct UiGrant: Codable {
    var operation: String
    var family: String
    var display: String
    var remaining_secs: UInt64
    var ttl_secs: UInt64
}

struct UiStatusRes: Codable {
    var agent_version: String
    var locked: Bool
    var sign_ttl_secs: UInt64
    var decrypt_ttl_secs: UInt64
    var idle_timeout_secs: UInt64
    var run_allow_len: Int
    var audit_push: Bool
    var revoked: Int?
    var grants: [UiGrant]
}

// MARK: - base64url (no padding), matching Rust BASE64_URL_SAFE_NO_PAD

func base64UrlNoPad(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// MARK: - ssh-agent wire client for ui-status@vt

/// Minimal ssh-agent protocol client: one connect per request (the agent is
/// connection-oriented and cheap on localhost). Framing per
/// draft-miller-ssh-agent: u32 BE length, then SSH_AGENTC_EXTENSION (27),
/// string(name), raw contents. Success reply is SSH_AGENT_EXTENSION_RESPONSE
/// (29) + string(name) + raw JSON; failure is SSH_AGENT_FAILURE (5).
enum AgentClient {
    static var socketPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/vt.sock")
    }

    enum Failure: LocalizedError {
        case noSocket      // connect refused / missing — agent not running
        case refused       // SSH_AGENT_FAILURE — no/wrong token, locked path, etc.
        case proto(String) // framing/decoding surprise

        var errorDescription: String? {
            switch self {
            case .noSocket: return "The agent is not reachable."
            case .refused: return "The agent refused the request."
            case .proto(let detail): return "Agent response error: \(detail)"
            }
        }
    }

    static func uiStatus(token: String, action: String) throws -> UiStatusRes {
        let req = UiStatusReq(token: token, action: action)
        let payload = try JSONEncoder().encode(req)
        let reply = try request(name: "ui-status@vt", payload: payload)
        return try JSONDecoder().decode(UiStatusRes.self, from: reply)
    }

    private static func request(name: String, payload: Data) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.noSocket }
        defer { close(fd) }

        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count <= capacity else { throw Failure.proto("socket path too long") }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            pathBytes.withUnsafeBufferPointer { raw.update(from: $0.baseAddress!, count: $0.count) }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        guard connected == 0 else { throw Failure.noSocket }

        // Frame: u32 BE length | 27 | u32 name-len | name | payload
        var body = Data([27])
        var nameLen = UInt32(name.utf8.count).bigEndian
        body.append(Data(bytes: &nameLen, count: 4))
        body.append(name.data(using: .utf8)!)
        body.append(payload)
        var frameLen = UInt32(body.count).bigEndian
        var frame = Data(bytes: &frameLen, count: 4)
        frame.append(body)
        try writeAll(fd, frame)

        let lenBytes = try readExactly(fd, 4)
        let replyLen = lenBytes.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard replyLen >= 1, replyLen < 16 * 1024 * 1024 else { throw Failure.proto("bad frame") }
        let reply = try readExactly(fd, Int(replyLen))

        switch reply[reply.startIndex] {
        case 29: // SSH_AGENT_EXTENSION_RESPONSE: string(name) + raw payload
            var offset = reply.startIndex + 1
            guard reply.count >= 5 else { throw Failure.proto("short reply") }
            let n = reply.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                Int($0.load(as: UInt32.self).bigEndian)
            }
            offset += 4 + n
            guard offset <= reply.endIndex else { throw Failure.proto("bad name len") }
            return reply.subdata(in: offset..<reply.endIndex)
        case 5, 28: // SSH_AGENT_FAILURE / SSH_AGENT_EXTENSION_FAILURE
            throw Failure.refused
        default:
            throw Failure.proto("unexpected reply type \(reply[reply.startIndex])")
        }
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var sent = 0
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                guard n > 0 else { throw Failure.proto("write failed") }
                sent += n
            }
        }
    }

    private static func readExactly(_ fd: Int32, _ count: Int) throws -> Data {
        var buf = Data(count: count)
        var got = 0
        try buf.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            while got < count {
                let n = read(fd, raw.baseAddress! + got, count - got)
                guard n > 0 else { throw Failure.proto("short read") }
                got += n
            }
        }
        return buf
    }
}

// MARK: - notify helper mode (`VT notify --title T --body B`)

func runNotifyMode(_ args: [String]) -> Never {
    var title = "VT"
    var body = ""
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--title": if i + 1 < args.count { title = args[i + 1]; i += 1 }
        case "--body": if i + 1 < args.count { body = args[i + 1]; i += 1 }
        default: break
        }
        i += 1
    }

    let center = UNUserNotificationCenter.current()
    let done = DispatchSemaphore(value: 0)
    var ok = false
    center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
        guard granted else { done.signal(); return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(
            identifier: UUID().uuidString, content: content, trigger: nil)
        center.add(request) { error in
            ok = (error == nil)
            done.signal()
        }
    }
    // First use can show the system permission dialog; cap the wait so the
    // agent's reaper thread never hangs on us.
    _ = done.wait(timeout: .now() + 30)
    exit(ok ? 0 : 1)
}

// MARK: - bounded, nonblocking agent stderr capture

final class AgentStderrCapture {
    static let capacity = 64 * 1024
    private let queue = DispatchQueue(label: "vt.agent-stderr")
    private let source: DispatchSourceRead
    private let fd: Int32
    private var tail = Data()
    private var stopped = false

    init(pipe: Pipe) throws {
        fd = pipe.fileHandleForReading.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.drain() }
        let reader = pipe.fileHandleForReading
        source.setCancelHandler { reader.closeFile() }
        source.resume()
    }

    private func drain() {
        guard !stopped else { return }
        var buffer = [UInt8](repeating: 0, count: 4096)
        // Bound each turn so a noisy descendant cannot starve finish().
        for _ in 0..<16 {
            let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
            if count > 0 {
                tail.append(contentsOf: buffer.prefix(count))
                if tail.count > Self.capacity { tail.removeFirst(tail.count - Self.capacity) }
            } else if count == 0 {
                stop()
                return
            } else if errno != EINTR {
                if errno != EAGAIN && errno != EWOULDBLOCK { stop() }
                return
            }
        }
    }

    private func stop() {
        guard !stopped else { return }
        stopped = true
        source.cancel()
    }

    func finish(_ completion: @escaping (String) -> Void) {
        queue.async {
            self.drain()
            self.stop()
            // Never wait for EOF: run@vt/notification descendants may still
            // hold stderr after the managed process has already exited.
            completion(String(decoding: self.tail, as: UTF8.self))
        }
    }

    deinit { source.cancel() }
}

// MARK: - managed agent supervisor

final class AgentSupervisor {
    /// UserDefaults keys for the menu-chosen cache durations. Absent = pass
    /// no flag (the agent's `[agent]` config / built-in default governs);
    /// present = pass an explicit spawn flag that overrides both.
    static let signCacheKey = "vt.signCacheSecs"
    static let decryptCacheKey = "vt.decryptCacheSecs"
    static let idleTimeoutKey = "vt.idleTimeoutSecs"

    /// Why the managed agent exited — drives the terminationHandler.
    private enum ExitIntent { case crash, stop, restart }

    /// base64url token for ui-status requests; nil = degraded (external agent
    /// or none).
    private(set) var tokenB64: String?
    /// Last start-failure hint (last stderr line of a fast-failing agent),
    /// surfaced in the menu. Cleared on a healthy start.
    private(set) var lastError: String?
    private var process: Process?
    private var intent: ExitIntent = .crash
    private var startedAt: TimeInterval = 0
    private var restartCount = 0
    private var generation: UInt64 = 0
    var onStateChange: (() -> Void)?

    var isManaged: Bool { process?.isRunning == true }

    func startIfNeeded() {
        guard process == nil else { return }
        // Never fight an externally-started agent for the socket.
        if agentListening() { return }
        start()
    }

    /// Deliberate stop then fresh start — used for a version-skew upgrade
    /// (`just install-app` replaced the binary; the running agent still runs
    /// the old code). Bypasses the external-agent guard: we own this one.
    func restart() {
        guard let proc = process else { startIfNeeded(); return }
        intent = .restart
        tokenB64 = nil
        if proc.isRunning { proc.terminate() }
        onStateChange?()
    }

    private func scheduleStart(after delay: TimeInterval) {
        let expected = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.generation == expected, self.process == nil else { return }
            self.startIfNeeded()
        }
    }

    private func agentListening() -> Bool {
        // A refused ui-status still proves something is listening.
        do {
            _ = try AgentClient.uiStatus(token: "", action: "status")
            return true
        } catch AgentClient.Failure.refused {
            return true
        } catch {
            return false
        }
    }

    func start() {
        guard process == nil else { return }
        guard let vt = Bundle.main.path(forAuxiliaryExecutable: "vt") else { return }
        generation &+= 1
        var tokenBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &tokenBytes) == errSecSuccess else { return }
        let token = Data(tokenBytes)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: vt)
        // Token over the stdin pipe (fd 0): inherited descriptor, never an
        // env var (`ps e`) or a file. The agent reads exactly 32 bytes and
        // closes it (docs/app-bundle.md §5).
        var arguments = ["ssh", "agent", "--ui-token-fd", "0"]
        // Menu-chosen durations (if any) as explicit spawn flags —
        // flag > config.toml [agent] > default. Absent key ⇒ no flag.
        let defaults = UserDefaults.standard
        if defaults.object(forKey: Self.signCacheKey) != nil {
            arguments += ["--ssh-auth-cache-duration", String(defaults.integer(forKey: Self.signCacheKey))]
        }
        if defaults.object(forKey: Self.decryptCacheKey) != nil {
            arguments += ["--decrypt-auth-cache-duration", String(defaults.integer(forKey: Self.decryptCacheKey))]
        }
        if defaults.object(forKey: Self.idleTimeoutKey) != nil {
            arguments += ["--timeout", String(defaults.integer(forKey: Self.idleTimeoutKey))]
        }
        proc.arguments = arguments
        let stdinPipe = Pipe()
        let errPipe = Pipe()
        proc.standardInput = stdinPipe
        proc.standardOutput = FileHandle.nullDevice
        // Capture stderr so a fast-failing agent (e.g. keychain wrap bound to
        // the old binary path — needs `vt secret rebind`) surfaces a reason
        // instead of a silent "not running".
        proc.standardError = errPipe
        let stderrCapture: AgentStderrCapture
        do {
            stderrCapture = try AgentStderrCapture(pipe: errPipe)
        } catch {
            lastError = "could not capture agent diagnostics: \(error.localizedDescription)"
            onStateChange?()
            return
        }
        // The wrap derivation needs USER; launchd contexts may lack it.
        var env = ProcessInfo.processInfo.environment
        if env["USER"] == nil { env["USER"] = NSUserName() }
        proc.environment = env

        let startTime = ProcessInfo.processInfo.systemUptime
        proc.terminationHandler = { [weak self] p in
            stderrCapture.finish { stderr in
                DispatchQueue.main.async {
                    guard let self, self.process === p else { return }
                    self.tokenB64 = nil
                    let intent = self.intent
                    self.intent = .crash
                    switch intent {
                    case .stop:
                        self.process = nil
                    case .restart:
                        self.process = nil
                        self.scheduleStart(after: 0.3)
                    case .crash:
                        // Fast exit (< 3s) = failed startup, not a long-run crash.
                        let fast = ProcessInfo.processInfo.systemUptime - startTime < 3
                        if fast || p.terminationStatus != 0 {
                            self.lastError = stderr
                                .split(separator: "\n")
                                .last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
                                .map(String.init)
                        }
                        self.process = nil
                        if self.restartCount < 5 {
                            self.restartCount += 1
                            self.scheduleStart(after: Double(self.restartCount) * 2)
                        }
                    }
                    self.onStateChange?()
                }
            }
        }
        do {
            try proc.run()
        } catch {
            errPipe.fileHandleForWriting.closeFile()
            stderrCapture.finish { _ in }
            lastError = "could not launch vt: \(error.localizedDescription)"
            onStateChange?()
            return
        }
        errPipe.fileHandleForWriting.closeFile()
        stdinPipe.fileHandleForWriting.write(token)
        stdinPipe.fileHandleForWriting.closeFile()
        process = proc
        startedAt = startTime
        intent = .crash
        tokenB64 = base64UrlNoPad(token)
        // Clear the stale-error hint once the agent survives past the
        // fast-fail window.
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self, self.process === proc, proc.isRunning else { return }
            self.restartCount = 0
            self.lastError = nil
            self.onStateChange?()
        }
        onStateChange?()
    }

    func stop() {
        generation &+= 1
        intent = .stop
        tokenB64 = nil
        if let proc = process, proc.isRunning {
            proc.terminate() // SIGTERM: ownership-checked socket cleanup
        }
        onStateChange?()
    }
}

// MARK: - menu bar icon (hex-nut key, template, code-drawn from icon.svg geometry)

func hexKeyTemplateImage(height: CGFloat) -> NSImage {
    // Geometry from cf-worker/pwa/icon.svg (512 viewBox). Content bounding
    // box in that space: x 152..360, y 90..412. We fit that box, aspect
    // preserved, into a padded status-bar cell so the glyph matches the
    // visual weight of SF Symbol menu-bar icons (which carry internal
    // padding) instead of filling the whole bar height.
    let contentMinX: CGFloat = 152, contentMinY: CGFloat = 90
    let contentW: CGFloat = 360 - 152, contentH: CGFloat = 412 - 90
    let pad: CGFloat = 0.5                      // minimal inset — fill the cell
    let avail = height - 2 * pad
    let scale = avail / contentH               // height-dominant (tall key)
    let drawW = contentW * scale
    let canvasW = drawW + 2 * pad
    let ox = pad, oy = pad

    let image = NSImage(size: NSSize(width: canvasW, height: height), flipped: true) { _ in
        func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
            NSPoint(x: ox + (x - contentMinX) * scale, y: oy + (y - contentMinY) * scale)
        }
        func r(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat) -> NSRect {
            NSRect(x: ox + (x - contentMinX) * scale, y: oy + (y - contentMinY) * scale,
                   width: w * scale, height: h * scale)
        }
        NSColor.black.setFill()
        // hex nut bow
        let hex = NSBezierPath()
        hex.move(to: p(360, 180))
        for (x, y) in [(308, 270), (204, 270), (152, 180), (204, 90), (308, 90)] {
            hex.line(to: p(CGFloat(x), CGFloat(y)))
        }
        hex.close()
        // keyhole punched out of the nut
        let hole = NSBezierPath()
        hole.appendOval(in: r(226, 136, 60, 60))
        hole.move(to: p(240, 182))
        hole.line(to: p(272, 182))
        hole.line(to: p(282, 246))
        hole.line(to: p(230, 246))
        hole.close()
        hex.append(hole.reversed)
        hex.windingRule = .evenOdd
        hex.fill()
        // shaft + teeth
        NSBezierPath(roundedRect: r(235, 250, 42, 162), xRadius: 18 * scale, yRadius: 18 * scale).fill()
        NSBezierPath(roundedRect: r(276, 330, 40, 24), xRadius: 6 * scale, yRadius: 6 * scale).fill()
        NSBezierPath(roundedRect: r(276, 372, 26, 24), xRadius: 6 * scale, yRadius: 6 * scale).fill()
        return true
    }
    image.isTemplate = true
    return image
}

// MARK: - app delegate / menu

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let supervisor = AgentSupervisor()
    private var pollTimer: Timer?
    private var lastStatus: UiStatusRes?
    private var agentReachable = false
    private var bundledVersion: String = ""
    private var revokeInFlight = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        bundledVersion = readBundledVtVersion()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        // Fill the status-bar cell like neighboring icons (~18pt).
        statusItem.button?.image = hexKeyTemplateImage(height: 18)
        statusItem.button?.imagePosition = .imageLeft
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        supervisor.onStateChange = { [weak self] in self?.poll() }
        supervisor.startIfNeeded()
        // Ask for notification permission at first launch so the agent's
        // notify helper calls never block on the permission dialog.
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }

        poll()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func readBundledVtVersion() -> String {
        guard let vt = Bundle.main.path(forAuxiliaryExecutable: "vt") else { return "" }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: vt)
        proc.arguments = ["version"]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = FileHandle.nullDevice
        guard (try? proc.run()) != nil else { return "" }
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        // `vt version` prints two lines:
        //   vt <version>            <- field 2 of the FIRST line only
        //   commit <sha> (<date>)
        // The version already carries its own leading "v"; do not add one.
        let text = String(data: data, encoding: .utf8) ?? ""
        guard let firstLine = text.split(separator: "\n").first else { return "" }
        let parts = firstLine.split(separator: " ")
        return parts.count >= 2 ? String(parts[1]) : ""
    }

    /// Refresh ui-status for icon/menu state. The socket I/O (blocking
    /// `connect`/`read`, up to a 5s timeout on a wedged agent) runs on a
    /// background queue — never the main thread — so a slow/mid-restart agent
    /// can't freeze the menu bar; only the state write + icon update hop back
    /// to main. Safe by construction: ui-status never resets the agent's idle
    /// clock (docs/app-bundle.md §5). Callers on main read the last result;
    /// the 3s timer keeps it fresh (≤3s stale on menu open).
    private func poll() {
        let token = supervisor.tokenB64 // read on main; supervisor mutates it on main
        DispatchQueue.global(qos: .utility).async { [weak self] in
            var status: UiStatusRes?
            var reachable = false
            if let token = token {
                status = try? AgentClient.uiStatus(token: token, action: "status")
                reachable = status != nil
            }
            if status == nil {
                // Degraded probe: refused = an agent listens but we hold no token.
                do {
                    _ = try AgentClient.uiStatus(token: "", action: "status")
                } catch AgentClient.Failure.refused {
                    reachable = true
                } catch {}
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.lastStatus = status
                self.agentReachable = reachable
                self.updateIcon()
            }
        }
    }

    private func updateIcon() {
        guard let button = statusItem.button else { return }
        button.appearsDisabled = !agentReachable
        if let s = lastStatus {
            if s.locked {
                button.title = " ⊘"
            } else if !s.grants.isEmpty {
                button.title = " \(s.grants.count)"
            } else {
                button.title = ""
            }
        } else {
            button.title = ""
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        poll()
        rebuildMenu(menu)
    }

    private func fmtRemaining(_ secs: UInt64) -> String {
        String(format: "%d:%02d", secs / 60, secs % 60)
    }

    private func rebuildMenu(_ menu: NSMenu) {
        menu.removeAllItems()

        // Status line (agent_version already carries its own leading "v")
        let statusText: String
        if let s = lastStatus {
            statusText = s.locked
                ? "Agent locked · \(s.agent_version)"
                : "Agent running · \(s.agent_version) · \(s.grants.count) grant\(s.grants.count == 1 ? "" : "s")"
        } else if agentReachable {
            statusText = "Agent running (started outside VT.app — limited view)"
        } else {
            statusText = "Agent not running"
        }
        menu.addItem(disabled(statusText))

        // Version skew: if we own the agent, offer a one-click upgrade
        // restart; otherwise it's an external agent we can only warn about.
        if let s = lastStatus, !bundledVersion.isEmpty, s.agent_version != bundledVersion {
            if supervisor.isManaged {
                addItem(menu, "⚠ Restart Agent to update (\(s.agent_version) → \(bundledVersion))",
                        #selector(restartAgent))
            } else {
                menu.addItem(disabled("⚠ agent \(s.agent_version) ≠ app \(bundledVersion) — restart agent"))
            }
        }

        // Managed agent failed to start (common cause: keychain wrap still
        // bound to the old binary path — run `vt secret rebind`).
        if !supervisor.isManaged, !agentReachable, let err = supervisor.lastError, !err.isEmpty {
            menu.addItem(disabled("⚠ agent failed to start:"))
            menu.addItem(disabled("   \(String(err.prefix(120)))"))
            addItem(menu, "Run Doctor…", #selector(runDoctor))
        }

        menu.addItem(.separator())

        // Grants
        if let s = lastStatus {
            if s.grants.isEmpty {
                menu.addItem(disabled(s.sign_ttl_secs == 0 && s.decrypt_ttl_secs == 0
                    ? "No grants (caching disabled — every request prompts)"
                    : "No live grants"))
            } else {
                let grantsItem = NSMenuItem(title: "Grants (\(s.grants.count))", action: nil, keyEquivalent: "")
                let sub = NSMenu()
                for g in s.grants {
                    sub.addItem(disabled("\(g.operation) · \(g.display.isEmpty ? g.family : g.display) · \(fmtRemaining(g.remaining_secs))"))
                }
                grantsItem.submenu = sub
                menu.addItem(grantsItem)
            }
            let revoke = NSMenuItem(title: "Revoke All Grants", action: #selector(revokeAll), keyEquivalent: "l")
            revoke.target = self
            menu.addItem(revoke)
        }

        // Cache duration (managed agent only — applying restarts the agent,
        // which reads the TTL at startup). Choices persist in UserDefaults
        // and are passed as spawn flags (§4/§6); the checkmark reflects the
        // agent's live TTL from ui-status, whatever its source.
        if let s = lastStatus, supervisor.isManaged {
            let cacheItem = NSMenuItem(title: "Cache Duration", action: nil, keyEquivalent: "")
            let sub = NSMenu()
            let sign = NSMenuItem(title: "Signing — \(AppDelegate.fmtTTL(s.sign_ttl_secs))", action: nil, keyEquivalent: "")
            sign.submenu = presetChoices(key: AgentSupervisor.signCacheKey, presets: Self.cachePresets, selector: #selector(setSignCache))
            sub.addItem(sign)
            let decrypt = NSMenuItem(title: "Decrypt — \(AppDelegate.fmtTTL(s.decrypt_ttl_secs))", action: nil, keyEquivalent: "")
            decrypt.submenu = presetChoices(key: AgentSupervisor.decryptCacheKey, presets: Self.cachePresets, selector: #selector(setDecryptCache))
            sub.addItem(decrypt)
            cacheItem.submenu = sub
            menu.addItem(cacheItem)

            // Idle timeout — VISIBLE so cache expiry is debuggable, not
            // "mysterious" (docs/app-bundle.md §10). Line shows the live
            // value; submenu configures it.
            let idleItem = NSMenuItem(
                title: "Idle timeout — \(AppDelegate.fmtTTL(s.idle_timeout_secs)) (clears cache when unused)",
                action: nil, keyEquivalent: "")
            idleItem.submenu = presetChoices(key: AgentSupervisor.idleTimeoutKey, presets: Self.idlePresets, selector: #selector(setIdleTimeout))
            menu.addItem(idleItem)
        }

        menu.addItem(.separator())

        // Agent control (managed only)
        if supervisor.isManaged {
            addItem(menu, "Stop Agent", #selector(stopAgent))
        } else if !agentReachable {
            addItem(menu, "Start Agent", #selector(startAgent))
        }

        // Login item
        if #available(macOS 13.0, *) {
            let login = NSMenuItem(title: "Start at Login", action: #selector(toggleLogin), keyEquivalent: "")
            login.target = self
            login.state = SMAppService.mainApp.status == .enabled ? .on : .off
            menu.addItem(login)
        }

        addItem(menu, "Run Doctor…", #selector(runDoctor))

        menu.addItem(.separator())
        addItem(menu, "Quit (agent keeps running)", #selector(quitKeepAgent))
        if supervisor.isManaged {
            addItem(menu, "Stop Agent and Quit", #selector(quitStopAgent))
        }
    }

    private func disabled(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func addItem(_ menu: NSMenu, _ title: String, _ sel: Selector) {
        let item = NSMenuItem(title: title, action: sel, keyEquivalent: "")
        item.target = self
        menu.addItem(item)
    }

    @objc private func revokeAll() {
        guard let token = supervisor.tokenB64, !revokeInFlight else { return }
        revokeInFlight = true
        DispatchQueue.global().async {
            // A timeout is not confirmation: the revoker may still be waiting
            // for a live permit, or this connection may have been interrupted.
            let result = Result { try AgentClient.uiStatus(token: token, action: "revoke_all") }
            DispatchQueue.main.async {
                self.revokeInFlight = false
                self.poll()
                if case .failure(let error) = result {
                    let alert = NSAlert()
                    alert.messageText = "Revocation not confirmed"
                    alert.informativeText = error.localizedDescription
                    alert.alertStyle = .warning
                    alert.runModal()
                }
            }
        }
    }

    @objc private func startAgent() { supervisor.startIfNeeded() }
    @objc private func stopAgent() { supervisor.stop() }
    @objc private func restartAgent() { supervisor.restart() }

    private static let cachePresets: [(String, Int)] = [
        ("Off (always prompt)", 0), ("5 minutes", 300), ("15 minutes", 900),
        ("1 hour", 3600), ("2 hours", 7200), ("8 hours", 28800),
    ]
    /// Tag sentinel for "remove the shell's override, let config.toml /
    /// default govern again". Distinct from any real second-count.
    private static let followConfigTag = -1

    static func fmtTTL(_ secs: UInt64) -> String {
        if secs == 0 { return "off" }
        if secs % 3600 == 0 { return "\(secs / 3600)h" }
        return "\(secs / 60)m"
    }

    // Idle-timeout presets. No "Off"/0 — idle 0 would busy-loop the agent
    // sweeper (agent also floors it at 60s). Cache presets are `cachePresets`
    // above (includes Off).
    private static let idlePresets: [(String, Int)] = [
        ("15 minutes", 900), ("30 minutes", 1800),
        ("1 hour", 3600), ("2 hours", 7200), ("8 hours", 28800),
    ]

    /// Build a preset submenu for one agent duration knob. `key` is the
    /// UserDefaults override key; the checkmark shows what the SHELL is doing
    /// (a specific override vs "Follow config file"), while the parent menu
    /// line carries the live effective value. Shared by the cache and
    /// idle-timeout submenus.
    private func presetChoices(key: String, presets: [(String, Int)], selector: Selector) -> NSMenu {
        let overridden = UserDefaults.standard.object(forKey: key) != nil
        let overrideVal = UserDefaults.standard.integer(forKey: key)
        let m = NSMenu()
        let follow = NSMenuItem(title: "Follow config file", action: selector, keyEquivalent: "")
        follow.target = self
        follow.tag = Self.followConfigTag
        follow.state = overridden ? .off : .on
        m.addItem(follow)
        m.addItem(.separator())
        for (label, secs) in presets {
            let it = NSMenuItem(title: label, action: selector, keyEquivalent: "")
            it.target = self
            it.tag = secs
            it.state = (overridden && secs == overrideVal) ? .on : .off
            m.addItem(it)
        }
        return m
    }

    // Persist the choice (spawn flag on next start) — or clear it to follow
    // config — then restart the managed agent so it takes effect. Dropping
    // current grants on restart is acceptable for a policy change.
    private func applyPreset(_ sender: NSMenuItem, key: String) {
        if sender.tag == AppDelegate.followConfigTag {
            UserDefaults.standard.removeObject(forKey: key)
        } else {
            UserDefaults.standard.set(sender.tag, forKey: key)
        }
        supervisor.restart()
    }

    // Thin @objc shims: the UserDefaults key can't ride an @objc selector, so
    // each knob needs its own one-line entry point delegating to applyPreset.
    @objc private func setSignCache(_ sender: NSMenuItem) {
        applyPreset(sender, key: AgentSupervisor.signCacheKey)
    }

    @objc private func setDecryptCache(_ sender: NSMenuItem) {
        applyPreset(sender, key: AgentSupervisor.decryptCacheKey)
    }

    @objc private func setIdleTimeout(_ sender: NSMenuItem) {
        applyPreset(sender, key: AgentSupervisor.idleTimeoutKey)
    }

    @objc private func toggleLogin() {
        if #available(macOS 13.0, *) {
            let service = SMAppService.mainApp
            do {
                if service.status == .enabled { try service.unregister() }
                else { try service.register() }
            } catch {
                NSLog("login item toggle failed: \(error)")
            }
        }
    }

    @objc private func runDoctor() {
        guard let vt = Bundle.main.path(forAuxiliaryExecutable: "vt") else { return }
        let script = "tell application \"Terminal\"\nactivate\ndo script \"\(vt) doctor\"\nend tell"
        if let osa = NSAppleScript(source: script) {
            osa.executeAndReturnError(nil)
        }
    }

    @objc private func quitKeepAgent() {
        // Deliberately do NOT stop the managed agent: it survives the UI and
        // keeps serving; the token dies with us so ui-status degrades until
        // the next shell start restarts it.
        NSApp.terminate(nil)
    }

    @objc private func quitStopAgent() {
        supervisor.stop()
        NSApp.terminate(nil)
    }
}

// MARK: - entry point

#if VT_LIFECYCLE_TEST

func captureForTest(script: String, keepWriterOpen: Bool = false) throws -> String {
    let pipe = Pipe()
    let heldWriter = keepWriterOpen ? dup(pipe.fileHandleForWriting.fileDescriptor) : -1
    if keepWriterOpen && heldWriter < 0 {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    defer { if heldWriter >= 0 { close(heldWriter) } }
    let capture = try AgentStderrCapture(pipe: pipe)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", script]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = pipe
    let done = DispatchSemaphore(value: 0)
    let resultLock = NSLock()
    var captured = ""
    process.terminationHandler = { _ in
        capture.finish { text in
            resultLock.lock()
            captured = text
            resultLock.unlock()
            done.signal()
        }
    }
    defer {
        try? pipe.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
    }
    try process.run()
    try? pipe.fileHandleForWriting.close()
    guard done.wait(timeout: .now() + 10) == .success else {
        throw NSError(domain: "VT lifecycle test timed out", code: 1)
    }
    guard process.terminationStatus == 0 else {
        throw NSError(domain: "VT lifecycle child failed", code: Int(process.terminationStatus))
    }
    resultLock.lock()
    defer { resultLock.unlock() }
    return captured
}

do {
    // More than any pipe capacity: a termination-only reader deadlocks here.
    let noisy = try captureForTest(script: """
        i=0
        while [ "$i" -lt 1024 ]; do
            printf '%4096s' ''
            i=$((i+1))
        done >&2
        printf '\\nfinished\\n' >&2
        """)
    precondition(noisy.utf8.count <= AgentStderrCapture.capacity, "stderr tail is unbounded")
    precondition(noisy.hasSuffix("finished\n"), "last diagnostics were lost")
    // Holding another writer is equivalent to a descendant retaining stderr.
    // Completion must not wait for EOF, which cannot occur until this returns.
    let held = try captureForTest(script: "printf 'held-writer\\n' >&2", keepWriterOpen: true)
    precondition(held == "held-writer\n", "termination snapshot lost buffered diagnostics")
    print("VT lifecycle tests: 2 passed")
} catch {
    FileHandle.standardError.write(Data("VT lifecycle test failed: \(error)\n".utf8))
    exit(1)
}

#else

let args = Array(CommandLine.arguments.dropFirst())
if args.first == "notify" {
    runNotifyMode(Array(args.dropFirst()))
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

#endif
