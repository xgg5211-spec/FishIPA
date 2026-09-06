import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            ScanView()
                .navigationTitle("小鱼优选")
                .navigationBarTitleDisplayMode(.inline)
        }
        .tint(.cyan)
    }
}

#Preview {
    ContentView()
}
