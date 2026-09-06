import Foundation
import Network
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

struct ScanResult: Identifiable, Hashable {
    let id: String
    let address: String
    let family: AddressFamily
    let latency: Double?
    let region: String?
    let error: String?

    var isAvailable: Bool { latency != nil }
    var displayLatency: String { latency.map { String(format: "%.0f ms", $0) } ?? "失败" }
}

private enum ProbeError: LocalizedError {
    case timeout
    var errorDescription: String? { "连接超时" }
}

private enum NetworkProbe {
    static func measure(address: String, port: UInt16, mode: ProbeMode, timeout: TimeInterval) async -> ScanResult {
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
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            let region = mode == .tls ? try? await traceRegion(connection, timeout: timeout) : nil
            connection.cancel()
            return ScanResult(id: address, address: address, family: family, latency: elapsed, region: region ?? nil, error: nil)
        } catch {
            return ScanResult(id: address, address: address, family: family, latency: nil, region: nil, error: error.localizedDescription)
        }
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
                finish(.failure(ProbeError.timeout))
            }
        }
    }

    private static func traceRegion(_ connection: NWConnection, timeout: TimeInterval) async throws -> String? {
        let request = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n"
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String?, Error>) in
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
                            finish(.success(label.isEmpty ? nil : label))
                            return
                        }
                        if isComplete || buffer.count > 64 * 1024 { finish(.success(nil)); return }
                        receiveMore()
                    }
                }
                receiveMore()
            })
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                finish(.success(nil))
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
    @Published var portText = "443"
    @Published var concurrencyText = "80"
    @Published var timeoutText = "2"
    @Published var family: AddressFamily = .all
    @Published var onlyAvailable = true
    @Published var searchText = ""

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

    var filteredResults: [ScanResult] {
        results.filter { result in
            (family == .all || result.family == family) &&
            (!onlyAvailable || result.isAvailable) &&
            (searchText.isEmpty || result.address.localizedCaseInsensitiveContains(searchText))
        }
    }

    func startScan() {
        stopScan()
        let addresses = parseAddresses(inputText.isEmpty ? Self.defaultAddresses.joined(separator: "\n") : inputText)
        guard !addresses.isEmpty else {
            statusMessage = "没有识别到有效 IP，请粘贴 IPv4 或 IPv6 地址"
            return
        }

        let port = UInt16(portText) ?? 443
        let concurrency = min(max(Int(concurrencyText) ?? 80, 1), 200)
        let timeout = min(max(Double(timeoutText) ?? 2, 0.5), 10)
        let selectedMode = mode
        let currentID = UUID()
        scanID = currentID
        results = []
        scannedCount = 0
        totalCount = addresses.count
        isScanning = true
        statusMessage = "正在进行 \(selectedMode.rawValue)，共 \(addresses.count) 个地址"

        scanTask = Task { [weak self] in
            var pending = addresses
            while !pending.isEmpty {
                guard !Task.isCancelled else { return }
                let batch = Array(pending.prefix(concurrency))
                pending.removeFirst(batch.count)
                let batchResults = await withTaskGroup(of: ScanResult.self, returning: [ScanResult].self) { group in
                    for address in batch {
                        group.addTask {
                            await NetworkProbe.measure(address: address, port: port, mode: selectedMode, timeout: timeout)
                        }
                    }
                    var values: [ScanResult] = []
                    for await value in group { values.append(value) }
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

    func importFile(_ url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }

        let type = (url.pathExtension.lowercased())
        if ["png", "jpg", "jpeg", "heic", "heif", "webp"].contains(type) {
            let image = UIImage(contentsOfFile: url.path)
            guard let image else {
                statusMessage = "图片文件无法读取"
                return
            }
            statusMessage = "正在识别图片中的 IP..."
            recognizeAddresses(in: image)
            return
        }

        if let value = try? String(contentsOf: url, encoding: .utf8), !value.isEmpty {
            importText(value)
            return
        }
        if let data = try? Data(contentsOf: url), let value = String(data: data, encoding: .utf8), !value.isEmpty {
            importText(value)
            return
        }
        statusMessage = "文件不是可读取的文本或图片格式"
    }

    private func importText(_ rawText: String) {
        let addresses = parseAddresses(rawText)
        guard !addresses.isEmpty else {
            statusMessage = "未识别到有效 IP/端口地址，请检查文本内容"
            return
        }
        inputText = addresses.joined(separator: "\n")
        statusMessage = "已识别 \(addresses.count) 个有效地址，可直接开始扫描"
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
        UIPasteboard.general.string = filteredResults.map(\.address).joined(separator: "\n")
    }

    func copyFastestResult() -> Bool {
        guard let fastest = results.first(where: \.isAvailable) else { return false }
        UIPasteboard.general.string = fastest.address
        statusMessage = "已复制最快节点：\(fastest.address)"
        return true
    }

    var exportText: String {
        filteredResults.map { "\($0.address),\($0.family.rawValue),\($0.displayLatency),\($0.error ?? "")" }.joined(separator: "\n")
    }

    private func parseAddresses(_ text: String) -> [String] {
        var unique = Set<String>()
        var results: [String] = []

        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.replacingOccurrences(of: "\r", with: "")
            let splitTokens = line
                .replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "http://", with: "")
                .components(separatedBy: CharacterSet(charactersIn: " ,;，；|\t\n\r\"'()[]{}<>"))
            for rawValue in splitTokens {
                guard let candidate = normalizeAddressCandidate(rawValue) else { continue }
                guard unique.insert(candidate).inserted else { continue }
                results.append(candidate)
            }
        }

        return results
    }

    private func normalizeAddressCandidate(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }

        value = value.trimmingCharacters(in: CharacterSet(charactersIn: "[](){}<>\"'"))
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
            return host
        }

        if value.contains(":") {
            let components = value.split(separator: ":", omittingEmptySubsequences: false)
            if components.count > 2 {
                // IPv6 without brackets: normalize to the bare IPv6 literal, dropping any trailing port-like token if present.
                let candidate = String(value)
                guard isValidIP(candidate) else { return nil }
                return candidate
            }
            if components.count == 2 {
                let host = String(components[0])
                let portString = String(components[1])
                guard !host.isEmpty, let port = Int(portString), (1...65535).contains(port) else {
                    if isValidIP(value) { return value }
                    return nil
                }
                return host
            }
        }

        guard !value.contains("/") else { return nil }
        guard isValidIP(value) else { return nil }
        return value
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
                Label("小鱼优选", systemImage: "fish").font(.caption.bold()).foregroundStyle(.cyan)
                Spacer()
                Text("\(model.totalCount.formatted()) 个地址").font(.caption.monospaced()).foregroundStyle(.white.opacity(0.45))
            }
            Text("小鱼优选\nCloudflare 节点精测").font(.system(size: 32, weight: .bold, design: .rounded)).foregroundStyle(.white)
            Text("自动识别地区 · IPv4 / IPv6 · 自定义 IP / 端口一键复制").font(.subheadline).foregroundStyle(.white.opacity(0.58))
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
            HStack(spacing: 10) {
                smallButton("粘贴", icon: "doc.on.clipboard") { model.pasteFromClipboard() }
                smallButton("导入文件", icon: "arrow.up.doc") { showImporter = true }
                smallButton("清空", icon: "trash") { model.inputText = "" }
                Spacer()
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
            HStack(spacing: 8) {
                settingField("端口", text: $model.portText, width: 58)
                settingField("并发", text: $model.concurrencyText, width: 58)
                settingField("超时 s", text: $model.timeoutText, width: 58)
                Picker("协议", selection: $model.family) {
                    ForEach(AddressFamily.allCases) { Text($0.rawValue).tag($0) }
                }
                .tint(.cyan)
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
                Text("测速结果").font(.title3.bold()).foregroundStyle(.white)
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
                .buttonStyle(.bordered).tint(.cyan).disabled(model.filteredResults.isEmpty)
                ShareLink(item: model.exportText) { Image(systemName: "square.and.arrow.up") }
                    .buttonStyle(.bordered).tint(.cyan).disabled(model.filteredResults.isEmpty)
            }
            if model.filteredResults.isEmpty {
                Text("没有结果。粘贴 IP 地址后开始扫描.")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.45)).padding(.vertical, 24)
            } else {
                ForEach(Array(model.filteredResults.prefix(500).enumerated()), id: \.element.id) { index, result in
                    resultRow(result, rank: index + 1)
                }
                if model.filteredResults.count > 500 {
                    Text("已显示前 500 条，复制和导出仍包含全部 \(model.filteredResults.count) 条结果")
                        .font(.caption).foregroundStyle(.white.opacity(0.45))
                }
            }
        }
    }

    private func resultRow(_ result: ScanResult, rank: Int) -> some View {
        HStack(spacing: 10) {
            Text(rank < 10 ? "0\(rank)" : "\(rank)").font(.caption.monospacedDigit().bold()).foregroundStyle(rank < 4 ? .cyan : .white.opacity(0.35)).frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(result.address).font(.body.monospaced().weight(.semibold)).foregroundStyle(.white)
                Text("\(result.family.rawValue) · \(result.region ?? "地区识别中") · \(result.isAvailable ? "\(model.mode.rawValue)成功" : (result.error ?? "失败"))").font(.caption).foregroundStyle(.white.opacity(0.45))
            }
            Spacer()
            Text(result.displayLatency).font(.subheadline.monospacedDigit().bold()).foregroundStyle(result.isAvailable ? (result.latency! < 100 ? .green : .orange) : .white.opacity(0.35))
            Button {
                UIPasteboard.general.string = result.address
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
            TextField(title, text: text).keyboardType(.numberPad).textFieldStyle(.roundedBorder).frame(width: width)
        }
    }
}

#Preview { NavigationStack { ScanView() } }
