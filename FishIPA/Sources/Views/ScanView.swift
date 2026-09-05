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

    private let cloudflareAddresses = [
        "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
        "162.159.36.1", "162.159.46.1", "162.159.192.1", "162.159.193.1",
        "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1",
        "104.20.0.1", "104.21.0.1", "104.22.0.1", "104.23.0.1"
    ]

    deinit {
        connections.forEach { $0.cancel() }
    }

    func startScan() {
        stopScan()
        scanToken = UUID()
        let token = scanToken
        let addresses = cloudflareAddresses
        isScanning = true
        scannedCount = 0
        totalCount = addresses.count
        results = []

        for address in addresses {
            measure(address: address, token: token)
        }
    }

    func stopScan() {
        scanToken = UUID()
        connections.forEach { $0.cancel() }
        connections.removeAll()
        isScanning = false
    }

    private func measure(address: String, token: UUID) {
        let connection = NWConnection(
            host: NWEndpoint.Host(address),
            port: 443,
            using: .tcp
        )
        connections.append(connection)
        let startedAt = DispatchTime.now().uptimeNanoseconds
        var completed = false

        func finish(latency: Double?, error: String?) {
            guard !completed else { return }
            completed = true
            connection.cancel()
            guard token == scanToken else { return }

            let result = ScanResult(address: address, latency: latency, error: error)
            scannedCount += 1
            results.append(result)
            results.sort {
                switch ($0.latency, $1.latency) {
                case let (left?, right?): return left < right
                case (_?, nil): return true
                default: return false
                }
            }
            if scannedCount >= totalCount {
                isScanning = false
            }
        }

        connection.stateUpdateHandler = { [weak self] state in
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch state {
                case .ready:
                    self.completeOnMain(finish: finish, latency: elapsed, error: nil)
                case .failed(let error):
                    self.completeOnMain(finish: finish, latency: nil, error: error.localizedDescription)
                case .cancelled:
                    if token == self.scanToken && !completed {
                        self.completeOnMain(finish: finish, latency: nil, error: "已取消")
                    }
                default:
                    break
                }
            }
        }
        connection.start(queue: .global(qos: .userInitiated))

        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 3) {
            Task { @MainActor [weak self] in
                guard let self, token == self.scanToken else { return }
                self.completeOnMain(finish: finish, latency: nil, error: "连接超时")
            }
        }
    }

    private func completeOnMain(
        finish: (@escaping (Double?, String?) -> Void),
        latency: Double?,
        error: String?
    ) {
        finish(latency, error)
    }
}

struct ScanView: View {
    @StateObject private var viewModel = ScanViewModel()

    var body: some View {
        VStack(spacing: 0) {
            header
            progress
            resultList
        }
        .background(Color(uiColor: .systemGroupedBackground))
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Cloudflare IP 测速")
                        .font(.title2.bold())
                    Text("通过 TCP 443 连接延迟，找到更快的节点")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.title2)
                    .foregroundStyle(.blue)
                    .padding(12)
                    .background(.blue.opacity(0.12), in: Circle())
            }

            Button {
                if viewModel.isScanning {
                    viewModel.stopScan()
                } else {
                    viewModel.startScan()
                }
            } label: {
                Label(
                    viewModel.isScanning ? "停止测速" : "开始扫描",
                    systemImage: viewModel.isScanning ? "stop.fill" : "play.fill"
                )
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .padding(20)
        .background(Color(uiColor: .systemBackground))
    }

    @ViewBuilder
    private var progress: some View {
        if viewModel.isScanning {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("正在扫描节点")
                    Spacer()
                    Text("\(viewModel.scannedCount)/\(viewModel.totalCount)")
                        .foregroundStyle(.secondary)
                }
                .font(.subheadline.weight(.medium))
                ProgressView(value: Double(viewModel.scannedCount), total: Double(max(viewModel.totalCount, 1)))
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(Color(uiColor: .systemBackground))
        }
    }

    private var resultList: some View {
        List {
            Section {
                if viewModel.results.isEmpty && !viewModel.isScanning {
                    ContentUnavailableView(
                        "等待开始扫描",
                        systemImage: "speedometer",
                        description: Text("将测试 Cloudflare 常用边缘 IP 的连接延迟")
                    )
                    .listRowBackground(Color.clear)
                } else {
                    ForEach(viewModel.results) { result in
                        resultRow(result)
                    }
                }
            } header: {
                HStack {
                    Text("测速结果")
                    Spacer()
                    if !viewModel.results.isEmpty {
                        Text("按延迟排序")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func resultRow(_ result: ScanResult) -> some View {
        HStack(spacing: 14) {
            Image(systemName: result.isAvailable ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(result.isAvailable ? .green : .red)
                .font(.title3)
            VStack(alignment: .leading, spacing: 3) {
                Text(result.address)
                    .font(.body.monospaced().weight(.medium))
                Text(result.isAvailable ? "TCP 连接成功" : (result.error ?? "连接失败"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let latency = result.latency {
                Text("\(latency, specifier: "%.0f") ms")
                    .font(.headline.monospacedDigit())
                    .foregroundStyle(latency < 100 ? .green : latency < 200 ? .orange : .red)
            } else {
                Text("失败")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 5)
    }
}

#Preview {
    NavigationStack { ScanView() }
}
