import Foundation
import Network
import SwiftUI
import UniformTypeIdentifiers

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
    let error: String?

    var isAvailable: Bool { latency != nil }
    var displayLatency: String { latency.map { "\($0, specifier: "%.0f") ms" } ?? "失败" }
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
            try await connect(host: NWEndpoint.Host(address), port: NWEndpoint.Port(rawValue: port) ?? 443, parameters: parameters, timeout: timeout)
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            return ScanResult(id: address, address: address, family: family, latency: elapsed, error: nil)
        } catch {
            return ScanResult(id: address, address: address, family: family, latency: nil, error: error.localizedDescription)
        }
    }

    private static func connect(host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters, timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let connection = NWConnection(host: host, port: port, using: parameters)
            let lock = NSLock()
            var completed = false

            func finish(_ result: Result<Void, Error>) {
                lock.lock()
                guard !completed else { lock.unlock(); return }
                completed = true
                lock.unlock()
                connection.cancel()
                continuation.resume(with: result)
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
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
}

@MainActor
final class ScanViewModel: ObservableObject {
    @Published private(set) var results: [ScanResult] = []
    @Published private(set) var isScanning = false
    @Published private(set) var scannedCount = 0
    @Published private(set) var totalCount = 0
    @Published var inputText = ""
    @Published var mode: ProbeMode = .tls
    @Published var portText = "443"
    @Published var concurrencyText = "80"
    @Published var timeoutText = "2"
    @Published var family: AddressFamily = .all
    @Published var onlyAvailable = true
    @Published var searchText = ""

    private var scanTask: Task<Void, Never>?
    private var scanID = UUID()

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
        let addresses = parseAddresses(inputText)
        guard !addresses.isEmpty else { return }

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
        }
    }

    func stopScan() {
        scanID = UUID()
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }

    func pasteFromClipboard() {
        if let value = UIPasteboard.general.string { inputText = value }
    }

    func importFile(_ url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        if let value = try? String(contentsOf: url, encoding: .utf8) { inputText = value }
    }

    func copyVisibleResults() {
        UIPasteboard.general.string = filteredResults.map(\.address).joined(separator: "\n")
    }

    var exportText: String {
        filteredResults.map { "\($0.address),\($0.family.rawValue),\($0.displayLatency),\($0.error ?? "")" }.joined(separator: "\n")
    }

    private func parseAddresses(_ text: String) -> [String] {
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ",;，；"))
        var unique = Set<String>()
        return text.components(separatedBy: separators).compactMap { raw in
            var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if value.hasPrefix("[") && value.hasSuffix("]") { value.removeFirst(); value.removeLast() }
            guard !value.isEmpty, !value.contains("/") else { return nil }
            if let lastColon = value.lastIndex(of: ":"), value[..<lastColon].contains("."), Int(value[value.index(after: lastColon)...]) != nil {
                value = String(value[..<lastColon])
            }
            guard value.count <= 45, value.allSatisfy({ $0.isNumber || $0 == "." || $0 == ":" || ($0 >= "a" && $0 <= "f") || ($0 >= "A" && $0 <= "F") }) else { return nil }
            guard unique.insert(value).inserted else { return nil }
            return value
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
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.plainText, .commaSeparatedText, .text]) { result in
            if case .success(let url) = result { model.importFile(url) }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Label("FISH IPA", systemImage: "water.waves").font(.caption.bold()).foregroundStyle(.cyan)
                Spacer()
                Text("\(model.totalCount.formatted()) 个地址").font(.caption.monospaced()).foregroundStyle(.white.opacity(0.45))
            }
            Text("Cloudflare 节点\n精测工具").font(.system(size: 32, weight: .bold, design: .rounded)).foregroundStyle(.white)
            Text("TLS 握手、IPv4 / IPv6、大批量 IP 一次处理").font(.subheadline).foregroundStyle(.white.opacity(0.58))
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
                Text("\(result.family.rawValue) · \(result.isAvailable ? "\(model.mode.rawValue)成功" : (result.error ?? "失败"))").font(.caption).foregroundStyle(.white.opacity(0.45))
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
