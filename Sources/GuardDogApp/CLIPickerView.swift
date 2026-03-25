import AppKit
import GuardDogCore
import SwiftUI

struct CLIPickerView: View {
    let onSelect: (String) -> Void
    let onCancel: () -> Void

    @State private var clis: [DiscoveredCLI] = []
    @State private var searchText = ""
    @State private var isScanning = true

    private var filtered: [DiscoveredCLI] {
        if searchText.isEmpty { return clis }
        let query = searchText.lowercased()
        return clis.filter {
            $0.name.lowercased().contains(query) || $0.path.lowercased().contains(query)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if isScanning {
                Spacer()
                ProgressView("Scanning for CLI tools…")
                Spacer()
            } else if filtered.isEmpty {
                Spacer()
                ContentUnavailableView.search(text: searchText)
                Spacer()
            } else {
                cliList
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 480)
        .task {
            let results = await Task.detached(priority: .userInitiated) {
                CLIDiscovery.discover()
            }.value
            clis = results
            isScanning = false
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Text("Add Protected Tool")
                .font(.headline)
            Text("Select an installed CLI to protect. GuardDog will control which apps can invoke it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            SearchField(text: $searchText, placeholder: "Filter by name or path…")
                .frame(height: 28)
        }
        .padding()
    }

    private var cliList: some View {
        List(filtered) { cli in
            Button {
                onSelect(cli.path)
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "terminal")
                        .foregroundStyle(.tint)
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cli.name)
                            .font(.body.weight(.medium))
                        Text(cli.path)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                    Image(systemName: "plus.circle")
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .listStyle(.plain)
    }

    private var footer: some View {
        HStack {
            Button("Browse…") {
                browseManually()
            }
            .buttonStyle(.bordered)

            Spacer()

            Text("\(filtered.count) tools found")
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()

            Button("Cancel") {
                onCancel()
            }
            .keyboardShortcut(.cancelAction)
        }
        .padding()
    }

    private func browseManually() {
        let panel = NSOpenPanel()
        panel.title = "Choose a CLI Executable"
        panel.prompt = "Protect Tool"
        panel.message = "Select a CLI executable to protect."
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.resolvesAliases = true
        panel.directoryURL = URL(fileURLWithPath: "/usr/local/bin", isDirectory: true)
        if panel.runModal() == .OK, let url = panel.url {
            onSelect(url.path)
        }
    }
}

/// An `NSSearchField` wrapper that reliably receives keyboard input in sheets
/// and hidden-title-bar windows where SwiftUI's `TextField` drops key events.
private struct SearchField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = placeholder
        field.delegate = context.coordinator
        field.focusRingType = .none
        field.bezelStyle = .roundedBezel
        // Become first responder once the field is installed in the window.
        DispatchQueue.main.async {
            field.window?.makeFirstResponder(field)
        }
        return field
    }

    func updateNSView(_ nsView: NSSearchField, context: Context) {
        if nsView.stringValue != text {
            nsView.stringValue = text
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        let parent: SearchField
        init(parent: SearchField) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            parent.text = field.stringValue
        }
    }
}
