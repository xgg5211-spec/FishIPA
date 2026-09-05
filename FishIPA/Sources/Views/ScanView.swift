import Network
import SwiftUI

struct ScanResult: Identifiable, Hashable {
    let id = UUID()
    let address: String
    let latency: Double?
    let error: String?
    var isAvailable: Bool { latency != nil }
}

@MainActor
final class ScanViewModel: ObservableObject {
    @Published private(set) var results: [ScanResult] = []
    @Published private(set) var isScanning = false
    @Published private(set) var scannedCount = 0
    @Published private(set) var totalCount = 0
    private var connections: [NWConnection] = []
    private var scanToken = UUID()

    // A quick mobile sample; the scheduled GitHub scan covers the upstream CIDR ranges.
    private let addresses = ["1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "162.159.36.1", "162.159.46.1", "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1", "104.20.0.1", "104.21.0.1", "104.22.0.1", "104.23.0.1", "172.64.0.1", "172.65.0.1"]

    func startScan() {
        stopScan()
        let token = UUID()
        scanToken = token
        results = []
        scannedCount = 0
        totalCount = addresses.count
        isScanning = true
        addresses.forEach { measure($0, token: token) }
    }

    func stopScan() {
        scanToken = UUID()
        connections.forEach { $0.cancel() }
        connections.removeAll()
        isScanning = false
    }

    private func measure(_ address: String, token: UUID) {
        let connection = NWConnection(host: NWEndpoint.Host(address), port: 443, using: .tcp)
        connections.append(connection)
        let start = DispatchTime.now().uptimeNanoseconds
        var finished = false

        func complete(_ latency: Double?, _ error: String?) {
            guard !finished else { return }
            finished = true
            connection.cancel()
            guard token == scanToken else { return }
            results.append(ScanResult(address: address, latency: latency, error: error))
            results.sort { ($0.latency ?? .greatestFiniteMagnitude) < ($1.latency ?? .greatestFiniteMagnitude) }
            scannedCount += 1
            if scannedCount == totalCount { isScanning = false }
        }

        connection.stateUpdateHandler = { [weak self] state in
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            Task { @MainActor [weak self] in
                guard let self, token == self.scanToken else { return }
                switch state {
                case .ready: complete(elapsed, nil)
                case .failed(let error): complete(nil, error.localizedDescription)
                default: break
                }
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2.5) {
            Task { @MainActor [weak self] in
                guard let self, token == self.scanToken else { return }
                complete(nil, "连接超时")
            }
        }
    }
}

struct ScanView: View {
    @StateObject private var model = ScanViewModel()
    @State private var showOnlyAvailable = false
    @State private var copiedAddress: String?

    private var visibleResults: [ScanResult] {
        showOnlyAvailable ? model.results.filter(\.isAvailable) : model.results
    }

    var body: some View {
        ZStack {
            Color(red: 0.035, green: 0.075, blue: 0.12).ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    hero
                    summary
                    controls
                    results
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
            }
        }
        .preferredColorScheme(.dark)
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("FISH IPA", systemImage: "water.waves")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.cyan)
                Spacer()
                Text("CF EDGE")
                    .font(.caption2.monospaced().weight(.bold))
                    .foregroundStyle(.white.opacity(0.45))
            }
            Text("找到更快的\nCloudflare 节点")
                .font(.system(size: 34, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
            Text("基于 TCP 443 连接延迟，结果越低越快。")
                .font(.subheadline)
                .foregroundStyle(.white.opacity(0.6))
        }
        .padding(.top, 10)
    }

    private var summary: some View {
        HStack(spacing: 10) {
            metric("最快", value: fastestLatency.map { "\($0) ms" } ?? "--", tint: .cyan)
            metric("可用", value: "\(model.results.filter(\.isAvailable).count)", tint: .green)
            metric("已测", value: "\(model.scannedCount)/\(model.totalCount)", tint: .orange)
        }
    }

    private var fastestLatency: Int? {
        model.results.compactMap(\.latency).min().map { Int($0.rounded()) }
    }

    private func metric(_ title: String, value: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.caption).foregroundStyle(.white.opacity(0.55))
            Text(value).font(.headline.monospacedDigit()).foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
    }

    private var controls: some View {
        VStack(spacing: 12) {
            Button {
                model.isScanning ? model.stopScan() : model.startScan()
            } label: {
                Label(model.isScanning ? "停止扫描" : "开始扫描", systemImage: model.isScanning ? "stop.fill" : "bolt.fill")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .tint(model.isScanning ? .red : .cyan)
            .controlSize(.large)
            .disabled(model.isScanning && model.scannedCount == model.totalCount)

            HStack {
                Label("仅显示可用节点", systemImage: "checkmark.circle")
                Spacer()
                Toggle("", isOn: $showOnlyAvailable).labelsHidden().tint(.cyan)
            }
            .font(.subheadline)
            .foregroundStyle(.white.opacity(0.75))
        }
        .padding(16)
        .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var results: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("测速排名").font(.title3.bold()).foregroundStyle(.white)
                Spacer()
                Text("TCP / 443").font(.caption.monospaced()).foregroundStyle(.white.opacity(0.4))
            }
            if visibleResults.isEmpty {
                Text("点击开始扫描，查看附近最快的边缘 IP")
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.45))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 28)
            } else {
                ForEach(Array(visibleResults.enumerated()), id: \.element.id) { index, result in
                    resultRow(result, rank: index + 1)
                }
            }
        }
    }

    private func resultRow(_ result: ScanResult, rank: Int) -> some View {
        HStack(spacing: 12) {
            Text(rank < 10 ? "0\(rank)" : "\(rank)").font(.caption.monospacedDigit().bold()).foregroundStyle(rank < 4 ? .cyan : .white.opacity(0.35)).frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(result.address).font(.body.monospaced().weight(.semibold)).foregroundStyle(.white)
                Text(result.isAvailable ? "连接成功" : (result.error ?? "连接失败")).font(.caption).foregroundStyle(.white.opacity(0.45))
            }
            Spacer()
            Text(result.latency.map { "\($0, specifier: "%.0f") ms" } ?? "失败")
                .font(.subheadline.monospacedDigit().bold())
                .foregroundStyle(result.isAvailable ? (result.latency! < 100 ? .green : .orange) : .white.opacity(0.35))
            Button {
                UIPasteboard.general.string = result.address
                copiedAddress = result.address
            } label: {
                Image(systemName: copiedAddress == result.address ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white.opacity(0.5))
        }
        .padding(14)
        .background(.white.opacity(0.065), in: RoundedRectangle(cornerRadius: 14))
    }
}

#Preview { NavigationStack { ScanView() } }
