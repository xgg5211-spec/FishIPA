import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            ScanView()
                .navigationTitle("鱼儿优选")
                .navigationBarTitleDisplayMode(.inline)
        }
        .tint(.blue)
    }
}

#Preview {
    ContentView()
}
