import SwiftUI

@main
struct GuardDogApp: App {
    @State private var model = GuardDogAppModel()

    var body: some Scene {
        WindowGroup("GuardDog") {
            GuardDogRootView(model: model)
                .frame(minWidth: 1080, minHeight: 700)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Refresh Rules") {
                    Task {
                        await model.refresh()
                    }
                }
                .keyboardShortcut("r")
            }
        }
    }
}
