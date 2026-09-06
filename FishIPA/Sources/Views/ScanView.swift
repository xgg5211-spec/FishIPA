import Foundation
import Network
import PDFKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Vision

enum ProbeMode: String, CaseIterable, Identifiable {
    case tls = "TLS 握手"
    case tcp = "TCP 连接"

    var id: String { rawValue }
    var icon: String { self == .tls ? "lock.shield.fill" : "bolt.horizontal.fill" }
}

enum AddressFamily: String, CaseIterable, Identifiable {
    case all = "全部"
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"

    var id: String { rawValue }
}

enum RegionFilter: String, CaseIterable, Identifiable {
    case all = "全部地区"
    case us = "US"
    case eu = "EU"
    case asia = "亚洲"
    case other = "其他"

    var id: String { rawValue }
}

struct ScanResult: Identifiable, Hashable {
    let id: String
    let address: String
    let port: UInt16
    let family: AddressFamily
    let latency: Double?
    let bandwidthMbps: Double?
    let region: String?
    let error: String?

    var isAvailable: Bool { latency != nil }
    var displayLatency: String { latency.map { String(format: "%.0f ms", $0) } ?? "失败" }
    var displayBandwidth: String { bandwidthMbps.map { String(format: "%.1f Mbps", $0) } ?? "带宽未测" }
    var endpoint: String {
        let host = family == .ipv6 ? "[\(address)]" : address
        return "\(host):\(port)"
    }
}

private struct AddressTarget: Hashable {
    let address: String
    let port: UInt16?
}

private let automaticPorts: [UInt16] = [443, 2053, 2083, 2087, 2096, 8443]

private enum ProbeError: LocalizedError {
    case timeout
    var errorDescription: String? { "连接超时" }
}

private enum NetworkProbe {
    static func measure(address: String, port: UInt16, mode: ProbeMode, timeout: TimeInterval, shouldMeasureBandwidth: Bool) async -> ScanResult {
        let family: AddressFamily = address.contains(":") ? .ipv6 : .ipv4
        let start = DispatchTime.now().uptimeNanoseconds
        let parameters: NWParameters

        if mode == .tls {
            let tlsOptions = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, "speed.cloudflare.com")
            parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        } else {
            parameters = .tcp
        }

        do {
            let connection = try await connect(host: NWEndpoint.Host(address), port: NWEndpoint.Port(rawValue: port) ?? 443, parameters: parameters, timeout: timeout)
            let trace: (region: String?, elapsedMilliseconds: Double)?
            if mode == .tls {
                trace = try? await traceRegion(connection, startedAt: start, timeout: timeout)
            } else {
                trace = nil
            }
            guard mode != .tls || trace != nil else { throw ProbeError.timeout }
            let elapsed = trace?.elapsedMilliseconds ?? Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            let region = trace?.region
            let bandwidth = mode == .tls && shouldMeasureBandwidth ? try? await measureBandwidth(address: address, port: port, parameters: parameters, timeout: min(timeout, 1.5)) : nil
            connection.cancel()
            return ScanResult(id: "\(address):\(port)", address: address, port: port, family: family, latency: elapsed, bandwidthMbps: bandwidth, region: region, error: nil)
        } catch {
            return ScanResult(id: "\(address):\(port)", address: address, port: port, family: family, latency: nil, bandwidthMbps: nil, region: nil, error: error.localizedDescription)
        }
    }

    private static func measureBandwidth(address: String, port: UInt16, parameters: NWParameters, timeout: TimeInterval) async throws -> Double {
        let connection = try await connect(host: NWEndpoint.Host(address), port: NWEndpoint.Port(rawValue: port) ?? 443, parameters: parameters, timeout: timeout)
        defer { connection.cancel() }
        let request = "GET /__down?bytes=32768 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n"
        let started = DispatchTime.now().uptimeNanoseconds
        let received = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, Error>) in
            var buffer = Data()
            connection.send(content: request.data(using: .utf8), completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error); return }
                func receive() {
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { content, _, complete, error in
                        if let error { continuation.resume(throwing: error); return }
                        if let content { buffer.append(content) }
                        if complete || content == nil {
                            let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8))?.upperBound ?? buffer.startIndex
                            continuation.resume(returning: max(buffer.count - buffer.distance(from: buffer.startIndex, to: headerEnd), 0))
                            return
                        }
                        receive()
                    }
                }
                receive()
            })
        }
        let elapsed = max(Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000, 0.001)
        guard received > 0 else { throw ProbeError.timeout }
        return Double(received) * 8 / elapsed / 1_000_000
    }

    private static func connect(host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters, timeout: TimeInterval) async throws -> NWConnection {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<NWConnection, Error>) in
            let connection = NWConnection(host: host, port: port, using: parameters)
            let lock = NSLock()
            var completed = false

            func finish(_ result: Result<NWConnection, Error>) {
                lock.lock()
                guard !completed else { lock.unlock(); return }
                completed = true
                lock.unlock()
                continuation.resume(with: result)
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(connection))
                case .failed(let error): finish(.failure(error))
                case .cancelled: finish(.failure(ProbeError.timeout))
                default: break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                connection.cancel()
                finish(.failure(ProbeError.timeout))
            }
        }
    }

    private static func traceRegion(_ connection: NWConnection, startedAt: UInt64, timeout: TimeInterval) async throws -> (String?, Double) {
        let request = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n"
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(String?, Double), Error>) in
            let lock = NSLock()
            var completed = false
            func finish(_ result: Result<String?, Error>) {
                lock.lock()
                guard !completed else { lock.unlock(); return }
                completed = true
                lock.unlock()
                continuation.resume(with: result)
            }
            connection.send(content: request.data(using: .utf8), completion: .contentProcessed { error in
                if let error { finish(.failure(error)); return }
                var buffer = Data()
                func receiveMore() {
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { content, _, isComplete, error in
                        if let error { finish(.failure(error)); return }
                        if let content { buffer.append(content) }
                        if let text = String(data: buffer, encoding: .utf8), text.contains("\r\n\r\n") {
                            let values = text.split(whereSeparator: \.isNewline).reduce(into: [String: String]()) { result, line in
                                let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
                                if parts.count == 2 { result[parts[0]] = parts[1] }
                            }
                            let label = [values["loc"], values["colo"]].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
                            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000
                            finish(.success((label.isEmpty ? nil : label, elapsed)))
                            return
                        }
                        if isComplete || buffer.count > 64 * 1024 { finish(.success(nil)); return }
                        receiveMore()
                    }
                }
                receiveMore()
            })
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                finish(.failure(ProbeError.timeout))
            }
        }
    }
}

@MainActor
final class ScanViewModel: ObservableObject {
    @Published private(set) var results: [ScanResult] = []
    @Published private(set) var isScanning = false
    @Published private(set) var scannedCount = 0
    @Published private(set) var totalCount = 0
    @Published var inputText: String
    @Published private(set) var statusMessage = "已载入 Cloudflare 默认节点"
    @Published var mode: ProbeMode = .tls
    @Published var portText = "自动"
    @Published var concurrencyText = "80"
    @Published var timeoutText = "2"
    @Published var family: AddressFamily = .all
    @Published var onlyAvailable = true
    @Published var searchText = ""
    @Published private(set) var isUpdatingPool = false
    @Published var regionFilter: RegionFilter = .all
    @Published var countryCode = ""
    @Published var selectedCountry = "全部国家"
    @Published var preferredCountText = "20"
    @Published var selectedPort = "全部端口"
    @Published var expectedBandwidthText = "0"
    @Published var useOfficialIPv4 = true
    @Published var useOfficialIPv6 = true
    @Published var officialCIDR = ""

    private var scanTask: Task<Void, Never>?
    private var scanID = UUID()

    private static let defaultAddresses = [
        "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
        "162.159.36.1", "162.159.46.1", "162.159.192.1", "162.159.193.1",
        "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1",
        "104.20.0.1", "104.21.0.1", "104.22.0.1", "104.23.0.1",
        "2606:4700:4700::1111", "2606:4700:4700::1001"
    ]

    init() {
        inputText = Self.defaultAddresses.joined(separator: "\n")
    }

    var availableCount: Int { results.reduce(into: 0) { if $1.isAvailable { $0 += 1 } } }
    var fastestLatency: Int? { results.compactMap(\.latency).min().map { Int($0.rounded()) } }

    var countryOptions: [String] {
        ["全部国家"] + countryCounts.keys.sorted()
    }

    var portOptions: [String] {
        ["全部端口"] + Set(results.map { String($0.port) }).sorted { (Int($0) ?? 0) < (Int($1) ?? 0) }
    }

    var countryCounts: [String: Int] {
        results.reduce(into: [String: Int]()) { counts, result in
            guard let country = result.region?.split(separator: "·").first?.trimmingCharacters(in: .whitespaces), !country.isEmpty else { return }
            counts[country, default: 0] += 1
        }
    }

    var preferredResults: [ScanResult] {
        let count = max(Int(preferredCountText) ?? 20, 1)
        return filteredResults.prefix(count).map { $0 }
    }

    var filteredResults: [ScanResult] {
        results.filter { result in
            (family == .all || result.family == family) &&
            (!onlyAvailable || result.isAvailable) &&
            (selectedPort == "全部端口" || selectedPort == String(result.port)) &&
            meetsBandwidth(result.bandwidthMbps) &&
            matchesRegion(result.region) &&
            (searchText.isEmpty || result.address.localizedCaseInsensitiveContains(searchText))
        }
    }

    private func matchesRegion(_ region: String?) -> Bool {
        let value = region?.uppercased() ?? ""
        if selectedCountry != "全部国家" {
            return value.split(separator: "·").first?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() == selectedCountry.uppercased()
        }
        let requestedCountry = countryCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if !requestedCountry.isEmpty && !value.split(separator: "·").contains(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix(requestedCountry) }) {
            return false
        }
        guard regionFilter != .all else { return true }
        switch regionFilter {
        case .all: return true
        case .us: return value.contains("US") || value.contains("美国")
        case .eu: return ["DE", "FR", "NL", "GB", "EU", "德国", "法国"].contains { value.contains($0) }
        case .asia: return ["CN", "HK", "JP", "SG", "KR", "TW", "中国", "日本"].contains { value.contains($0) }
        case .other: return !value.isEmpty && !matchesKnownRegion(value)
        }
    }

    private func meetsBandwidth(_ measured: Double?) -> Bool {
        let expected = max(Double(expectedBandwidthText) ?? 0, 0)
        guard expected > 0 else { return true }
        guard let measured else { return true }
        return measured >= expected
    }

    private func matchesKnownRegion(_ value: String) -> Bool {
        matchesRegionValue(value, values: ["US", "美国", "DE", "FR", "NL", "GB", "EU", "德国", "法国", "CN", "HK", "JP", "SG", "KR", "TW", "中国", "日本"])
    }

    private func matchesRegionValue(_ value: String, values: [String]) -> Bool {
        values.contains { value.contains($0) }
    }

    func startScan() {
        stopScan()
        let targets = parseTargets(inputText.isEmpty ? Self.defaultAddresses.joined(separator: "\n") : inputText)
        guard !targets.isEmpty else {
            statusMessage = "没有识别到有效 IP，请粘贴 IPv4 或 IPv6 地址"
            return
        }

        let requestedPort = UInt16(portText)
        let concurrency = min(max(Int(concurrencyText) ?? 80, 1), 1000)
        let timeout = min(max(Double(timeoutText) ?? 2, 0.5), 10)
        let selectedMode = mode
        let measureBandwidth = selectedMode == .tls
        let currentID = UUID()
        scanID = currentID
        results = []
        scannedCount = 0
        totalCount = targets.count
        isScanning = true
        statusMessage = "正在进行 \(selectedMode.rawValue)，并发上限 \(concurrency)，自动端口会取最快成功端口"

        scanTask = Task { [weak self] in
            var pending = targets
            while !pending.isEmpty {
                guard !Task.isCancelled else { return }
                let batch = Array(pending.prefix(concurrency))
                pending.removeFirst(batch.count)
                let batchResults = await withTaskGroup(of: ScanResult?.self, returning: [ScanResult].self) { group in
                    for target in batch {
                        group.addTask {
                            if let explicitPort = target.port ?? requestedPort {
                                return await NetworkProbe.measure(address: target.address, port: explicitPort, mode: selectedMode, timeout: timeout, shouldMeasureBandwidth: measureBandwidth)
                            }
                            var lastResult: ScanResult?
                            for candidatePort in automaticPorts {
                                let result = await NetworkProbe.measure(address: target.address, port: candidatePort, mode: selectedMode, timeout: timeout, shouldMeasureBandwidth: false)
                                lastResult = result
                                if result.isAvailable {
                                    if measureBandwidth {
                                        return await NetworkProbe.measure(address: result.address, port: result.port, mode: selectedMode, timeout: timeout, shouldMeasureBandwidth: true)
                                    }
                                    return result
                                }
                            }
                            return lastResult
                        }
                    }
                    var values: [ScanResult] = []
                    for await value in group where value != nil { values.append(value!) }
                    return values
                }
                guard let self, self.scanID == currentID else { return }
                self.results.append(contentsOf: batchResults)
                self.results.sort { ($0.latency ?? .greatestFiniteMagnitude) < ($1.latency ?? .greatestFiniteMagnitude) }
                self.scannedCount += batchResults.count
            }
            guard let self, self.scanID == currentID else { return }
            self.isScanning = false
            self.scanTask = nil
            self.statusMessage = "扫描完成：可用 \(self.availableCount) / \(self.totalCount)"
        }
    }

    func stopScan() {
        scanID = UUID()
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }

    func pasteFromClipboard() {
        let pasteboard = UIPasteboard.general
        if let value = pasteboard.string, !value.isEmpty {
            importText(value)
            return
        }
        guard let image = pasteboard.image else {
            statusMessage = "剪贴板没有文本或图片"
            return
        }
        statusMessage = "正在识别图片中的 IP..."
        recognizeAddresses(in: image)
    }

    func updateFromGitHub() {
        guard !isUpdatingPool else { return }
        isUpdatingPool = true
        statusMessage = "正在更新 GitHub IP 库..."
        let url = URL(string: "https://raw.githubusercontent.com/xgg5211-spec/FishIPA/master/data/edgetunnel/ADD.txt")!
        Task { [weak self] in
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
                      let text = String(data: data, encoding: .utf8) else { throw URLError(.badServerResponse) }
                let targets = self?.parseTargets(text) ?? []
                guard !targets.isEmpty else { throw URLError(.cannotParseResponse) }
                self?.inputText = targets.map { target in
                    let host = target.address.contains(":") ? "[\(target.address)]" : target.address
                    return target.port.map { "\(host):\($0)" } ?? host
                }.joined(separator: "\n")
                self?.statusMessage = "已更新 IP 库：\(targets.count) 个地址"
            } catch {
                self?.statusMessage = "IP 库更新失败：\(error.localizedDescription)"
            }
            self?.isUpdatingPool = false
        }
    }

    func updateFromCloudflare() {
        guard !isUpdatingPool else { return }
        isUpdatingPool = true
        statusMessage = "正在读取 Cloudflare 官方 IPv4/IPv6 网段..."
        let urls = [
            URL(string: "https://www.cloudflare.com/ips-v4")!,
            URL(string: "https://www.cloudflare.com/ips-v6")!
        ]
        Task { [weak self] in
            do {
                let values = try await withThrowingTaskGroup(of: String.self, returning: [String].self) { group in
                    for url in urls {
                        group.addTask {
                            let (data, response) = try await URLSession.shared.data(from: url)
                            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
                                  let text = String(data: data, encoding: .utf8) else { throw URLError(.badServerResponse) }
                            return text
                        }
                    }
                    var output: [String] = []
                    for try await text in group { output.append(contentsOf: text.split(whereSeparator: \.isNewline).map(String.init)) }
                    return output
                }
                let targets = values.filter { cidr in
                    let isIPv6 = cidr.contains(":")
                    let familyEnabled = isIPv6 ? self?.useOfficialIPv6 == true : self?.useOfficialIPv4 == true
                    let requestedCIDR = self?.officialCIDR.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                    return familyEnabled && (requestedCIDR.isEmpty || requestedCIDR == cidr)
                }.flatMap(Self.sampleTargets(from:))
                guard !targets.isEmpty else { throw URLError(.cannotParseResponse) }
                self?.inputText = targets.map { target in
                    let host = target.address.contains(":") ? "[\(target.address)]" : target.address
                    return "\(host):\(target.port ?? 443)"
                }.joined(separator: "\n")
                self?.statusMessage = "已载入 Cloudflare 官方网段：\(targets.count) 个 TLS 节点"
            } catch {
                self?.statusMessage = "Cloudflare 官方 IP 库读取失败：\(error.localizedDescription)"
            }
            self?.isUpdatingPool = false
        }
    }

    private static func sampleTargets(from cidr: String) -> [AddressTarget] {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...128).contains(prefix) else { return [] }
        let ipv4 = parts[0].split(separator: ".").compactMap { UInt8($0) }
        if ipv4.count == 4, prefix <= 32 {
            let base = ipv4.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
            let network = base & mask
            let hostCount = max(min(UInt64(1) << UInt64(min(32 - prefix, 4)), 16), 1)
            return (1...hostCount).map { offset in
                let host = min(UInt64(network) + offset, UInt64(UInt32.max))
                let address = [host >> 24, host >> 16, host >> 8, host].map { String($0 & 255) }.joined(separator: ".")
                return AddressTarget(address: address, port: 443)
            }
        }
        if parts[0].contains(":") {
            let base = parts[0].hasSuffix("::") ? String(parts[0].dropLast(2)) : parts[0]
            return (1...8).map { AddressTarget(address: "\(base)::\($0)", port: 443) }
        }
        return []
    }

    func importFile(_ url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }

        let type = (url.pathExtension.lowercased())
        if ["png", "jpg", "jpeg", "heic", "heif", "webp"].contains(type) {
            let image = UIImage(data: (try? Data(contentsOf: url)) ?? Data())
            guard let image else {
                statusMessage = "图片文件无法读取"
                return
            }
            statusMessage = "正在识别图片中的 IP..."
            recognizeAddresses(in: image)
            return
        }

        if type == "pdf", let document = PDFDocument(url: url), let value = document.string, !value.isEmpty {
            importText(value)
            return
        }

        if let data = try? Data(contentsOf: url), !data.isEmpty {
            let value = String(decoding: data, as: UTF8.self)
            importText(value)
            return
        }
        statusMessage = "文件已读取，但没有识别到 IP 或网段"
    }

    private func importText(_ rawText: String) {
        let targets = parseTargets(rawText)
        guard !targets.isEmpty else {
            statusMessage = "未识别到有效 IP/端口地址，请检查文本内容"
            return
        }
        inputText = targets.map { target in
            let host = target.address.contains(":") ? "[\(target.address)]" : target.address
            return target.port.map { "\(host):\($0)" } ?? host
        }.joined(separator: "\n")
        statusMessage = "已识别 \(targets.count) 个有效地址，可直接开始扫描"
    }

    private func recognizeAddresses(in image: UIImage) {
        guard let cgImage = image.cgImage else {
            statusMessage = "图片格式无法识别"
            return
        }
        let request = VNRecognizeTextRequest { [weak self] request, error in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let error {
                    self.statusMessage = "图片识别失败：\(error.localizedDescription)"
                    return
                }
                let lines = (request.results as? [VNRecognizedTextObservation] ?? [])
                    .compactMap { $0.topCandidates(1).first?.string }
                let recognized = lines.joined(separator: "\n")
                guard !recognized.isEmpty else {
                    self.statusMessage = "图片中没有识别到文本"
                    return
                }
                self.inputText = recognized
                self.statusMessage = "已从图片识别文本，请检查后开始扫描"
            }
        }
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        request.recognitionLanguages = ["en-US", "zh-Hans"]
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
            } catch {
                Task { @MainActor [weak self] in
                    self?.statusMessage = "图片识别失败：\(error.localizedDescription)"
                }
            }
        }
    }

    func copyVisibleResults() {
        UIPasteboard.general.string = preferredResults.map(\.endpoint).joined(separator: "\n")
    }

    func copyFastestResult() -> Bool {
        guard let fastest = results.first(where: \.isAvailable) else { return false }
        UIPasteboard.general.string = fastest.endpoint
        statusMessage = "已复制最快节点：\(fastest.endpoint)"
        return true
    }

    var exportText: String {
        preferredResults.map(\.endpoint).joined(separator: "\n")
    }

    private func parseTargets(_ text: String) -> [AddressTarget] {
        var unique = Set<AddressTarget>()
        var results: [AddressTarget] = []

        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.replacingOccurrences(of: "\r", with: "")
            let splitTokens = line
                .replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "http://", with: "")
                .components(separatedBy: CharacterSet(charactersIn: " ,;，；|\t\n\r\"'(){}<>"))
            for rawValue in splitTokens {
                if rawValue.contains("/") {
                    results.append(contentsOf: Self.sampleTargets(from: rawValue))
                    continue
                }
                guard let candidate = normalizeAddressCandidate(rawValue) else { continue }
                guard unique.insert(candidate).inserted else { continue }
                results.append(candidate)
            }
        }

        return results
    }

    private func normalizeAddressCandidate(_ raw: String) -> AddressTarget? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }

        value = value.trimmingCharacters(in: CharacterSet(charactersIn: "(){}<>\"'"))
        if value.contains("#") {
            value = String(value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: true).first ?? "")
        }
        if value.contains("/") {
            value = String(value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).first ?? "")
        }
        if value.contains("?") {
            value = String(value.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: true).first ?? "")
        }
        if value.contains("@") {
            value = String(value.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: true).last ?? "")
        }

        if value.hasPrefix("[") && value.contains("]") {
            let endIndex = value.firstIndex(of: "]") ?? value.endIndex
            let host = String(value[value.index(after: value.startIndex)..<endIndex])
            let tail = String(value[endIndex...]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else { return nil }
            if tail.hasPrefix(":") {
                let portString = String(tail.dropFirst())
                guard let port = Int(portString), (1...65535).contains(port) else { return nil }
            } else if !tail.isEmpty {
                return nil
            }
            return AddressTarget(address: host, port: tail.hasPrefix(":") ? UInt16(String(tail.dropFirst())) : nil)
        }

        if value.contains(":") {
            let components = value.split(separator: ":", omittingEmptySubsequences: false)
            if components.count > 2 {
                // IPv6 without brackets: normalize to the bare IPv6 literal, dropping any trailing port-like token if present.
                let candidate = String(value)
                guard isValidIP(candidate) else { return nil }
                return AddressTarget(address: candidate, port: nil)
            }
            if components.count == 2 {
                let host = String(components[0])
                let portString = String(components[1])
                guard !host.isEmpty, let port = Int(portString), (1...65535).contains(port) else {
                    if isValidIP(value) { return AddressTarget(address: value, port: nil) }
                    return nil
                }
                return AddressTarget(address: host, port: UInt16(port))
            }
        }

        guard !value.contains("/") else { return nil }
        guard isValidIP(value) else { return nil }
        return AddressTarget(address: value, port: nil)
    }

    private func isValidIP(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return false }
        if trimmed.contains(":") {
            let hexChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF:")
            return trimmed.count <= 45 && trimmed.unicodeScalars.allSatisfy({ hexChars.contains($0) || $0 == ":" })
        }

        let blocks = trimmed.split(separator: ".")
        guard blocks.count == 4 else { return false }
        return blocks.allSatisfy { block in
            guard !block.isEmpty, block.count <= 3 else { return false }
            guard let number = Int(block), (0...255).contains(number) else { return false }
            return true
        }
    }
}

struct ScanView: View {
    @StateObject private var model = ScanViewModel()
    @State private var showImporter = false
    @State private var copied = false

    var body: some View {
        ZStack {
            Color(red: 0.035, green: 0.075, blue: 0.12).ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    inputPanel
                    controls
                    resultPanel
                }
                .padding(20)
            }
        }
        .preferredColorScheme(.dark)
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .text, .plainText, .commaSeparatedText, .item], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first { model.importFile(url) }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Label("小鱼优选", systemImage: "fish.fill").font(.caption.bold()).foregroundStyle(.cyan)
                Spacer()
                Text("\(model.totalCount.formatted()) 个地址").font(.caption.monospaced()).foregroundStyle(.white.opacity(0.45))
            }
            Text("小鱼优选\nCloudflare 节点优选").font(.system(size: 32, weight: .bold, design: .rounded)).foregroundStyle(.white)
            Text("真实 TLS 延迟 · 自动带宽 · 复制结果不含延迟").font(.subheadline).foregroundStyle(.white.opacity(0.58))
        }
    }

    private var inputPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("IP 地址池", systemImage: "square.stack.3d.up.fill").font(.headline).foregroundStyle(.white)
                Spacer()
                Text("支持粘贴 10,000+ 行").font(.caption).foregroundStyle(.cyan)
            }
            TextEditor(text: $model.inputText)
                .font(.system(.footnote, design: .monospaced))
                .scrollContentBackground(.hidden)
                .foregroundStyle(.white)
                .frame(minHeight: 120, maxHeight: 180)
                .padding(8)
                .background(.black.opacity(0.22), in: RoundedRectangle(cornerRadius: 12))
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                smallButton("粘贴", icon: "doc.on.clipboard") { model.pasteFromClipboard() }
                smallButton("导入文件", icon: "arrow.up.doc") { showImporter = true }
                smallButton(model.isUpdatingPool ? "更新中" : "Cloudflare 官方", icon: "cloud.fill") { model.updateFromCloudflare() }
                smallButton(model.isUpdatingPool ? "更新中" : "更新 IP 库", icon: "arrow.triangle.2.circlepath") { model.updateFromGitHub() }
                smallButton("清空", icon: "trash") { model.inputText = "" }
                }
            }
        }
        .padding(15)
        .background(.white.opacity(0.065), in: RoundedRectangle(cornerRadius: 18))
    }

    private var controls: some View {
        VStack(spacing: 12) {
            Picker("探测方式", selection: $model.mode) {
                ForEach(ProbeMode.allCases) { mode in Label(mode.rawValue, systemImage: mode.icon).tag(mode) }
            }
            .pickerStyle(.segmented)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 78), spacing: 8)], spacing: 10) {
                settingField("端口", text: $model.portText, width: 58)
                settingField("并发", text: $model.concurrencyText, width: 58)
                settingField("超时 s", text: $model.timeoutText, width: 58)
                Picker("协议", selection: $model.family) {
                    ForEach(AddressFamily.allCases) { Text($0.rawValue).tag($0) }
                }
                .tint(.cyan)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("优选地区").font(.caption).foregroundStyle(.white.opacity(0.55))
                Picker("地区", selection: $model.regionFilter) {
                    ForEach(RegionFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                TextField("国家代码，可填 US / DE / JP", text: $model.countryCode)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                Picker("国家", selection: $model.selectedCountry) {
                    ForEach(model.countryOptions, id: \.self) { country in
                        Text("\(country) (\(model.countryCounts[country] ?? 0))").tag(country)
                    }
                }
                .tint(.cyan)
                Text("国家数量按 TLS 识别结果统计").font(.caption2).foregroundStyle(.white.opacity(0.4))
                settingField("每国优选数量", text: $model.preferredCountText, width: 110)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("Cloudflare 官方网段").font(.caption).foregroundStyle(.white.opacity(0.55))
                HStack {
                    Toggle("IPv4", isOn: $model.useOfficialIPv4).tint(.cyan)
                    Toggle("IPv6", isOn: $model.useOfficialIPv6).tint(.cyan)
                }
                TextField("指定网段，可填 104.16.0.0/13", text: $model.officialCIDR)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("结果筛选").font(.caption).foregroundStyle(.white.opacity(0.55))
                HStack {
                    Picker("端口", selection: $model.selectedPort) {
                        ForEach(model.portOptions, id: \.self) { port in
                            Text(port).tag(port)
                        }
                    }
                    .tint(.cyan)
                    settingField("期待带宽 Mbps", text: $model.expectedBandwidthText, width: 120)
                }
            }
            Button {
                model.isScanning ? model.stopScan() : model.startScan()
            } label: {
                Label(model.isScanning ? "停止扫描" : "开始精测", systemImage: model.isScanning ? "stop.fill" : "bolt.fill")
                    .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .buttonStyle(.borderedProminent).tint(model.isScanning ? .red : .cyan)
            if model.isScanning {
                ProgressView(value: Double(model.scannedCount), total: Double(max(model.totalCount, 1))).tint(.cyan)
                Text("已完成 \(model.scannedCount.formatted()) / \(model.totalCount.formatted())，有界并发不会阻塞界面")
                    .font(.caption).foregroundStyle(.white.opacity(0.5))
            }
            Text(model.statusMessage)
                .font(.caption)
                .foregroundStyle(model.statusMessage.contains("没有") ? .orange : .white.opacity(0.5))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(15)
        .background(.white.opacity(0.065), in: RoundedRectangle(cornerRadius: 18))
    }

    private var resultPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("优选结果").font(.title3.bold()).foregroundStyle(.white)
                Spacer()
                Text("最快 \(model.fastestLatency.map { "\($0) ms" } ?? "--")").font(.caption.monospaced()).foregroundStyle(.cyan)
            }
            HStack {
                TextField("搜索 IP", text: $model.searchText).textFieldStyle(.roundedBorder)
                Toggle("可用", isOn: $model.onlyAvailable).labelsHidden().tint(.cyan)
                Button {
                    copied = model.copyFastestResult()
                } label: { Image(systemName: "bolt.fill") }
                .buttonStyle(.bordered).tint(.orange).disabled(model.availableCount == 0)
                .accessibilityLabel("复制最快 IP")
                Button {
                    model.copyVisibleResults(); copied = true
                } label: { Image(systemName: copied ? "checkmark" : "square.on.square") }
                .buttonStyle(.bordered).tint(.cyan).disabled(model.preferredResults.isEmpty)
                ShareLink(item: model.exportText) { Image(systemName: "square.and.arrow.up") }
                    .buttonStyle(.bordered).tint(.cyan).disabled(model.preferredResults.isEmpty)
            }
            if model.filteredResults.isEmpty {
                Text("没有结果。粘贴 IP 地址后开始扫描.")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.45)).padding(.vertical, 24)
            } else {
                ForEach(Array(model.preferredResults.prefix(500).enumerated()), id: \.element.id) { index, result in
                    resultRow(result, rank: index + 1)
                }
                if model.filteredResults.count > 500 {
                    Text("当前筛选共 \(model.filteredResults.count) 条，已按每国数量显示优选结果")
                        .font(.caption).foregroundStyle(.white.opacity(0.45))
                }
            }
        }
    }

    private func resultRow(_ result: ScanResult, rank: Int) -> some View {
        HStack(spacing: 10) {
            Text(rank < 10 ? "0\(rank)" : "\(rank)").font(.caption.monospacedDigit().bold()).foregroundStyle(rank < 4 ? .cyan : .white.opacity(0.35)).frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(result.endpoint).font(.body.monospaced().weight(.semibold)).foregroundStyle(.white)
                Text("\(result.family.rawValue) · \(result.region ?? "地区识别中") · \(result.displayBandwidth) · \(result.isAvailable ? "\(model.mode.rawValue)成功" : (result.error ?? "失败"))").font(.caption).foregroundStyle(.white.opacity(0.45))
            }
            Spacer()
            Text(result.displayLatency).font(.subheadline.monospacedDigit().bold()).foregroundStyle(result.isAvailable ? (result.latency! < 100 ? .green : .orange) : .white.opacity(0.35))
            Button {
                UIPasteboard.general.string = result.endpoint
                copied = true
            } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(12)
        .background(.white.opacity(0.065), in: RoundedRectangle(cornerRadius: 13))
    }

    private func smallButton(_ title: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Label(title, systemImage: icon).font(.caption) }
            .buttonStyle(.bordered).tint(.cyan)
    }

    private func settingField(_ title: String, text: Binding<String>, width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption2).foregroundStyle(.white.opacity(0.5))
            TextField(title, text: text).keyboardType(.asciiCapable).textFieldStyle(.roundedBorder).frame(width: width)
        }
    }
}

#Preview { NavigationStack { ScanView() } }
