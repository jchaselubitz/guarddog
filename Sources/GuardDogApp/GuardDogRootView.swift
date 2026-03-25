import AppKit
import GuardDogCore
import SwiftUI

struct GuardDogRootView: View {
    @Bindable var model: GuardDogAppModel

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
        }
        .task {
            await model.refresh()
        }
        .alert("GuardDog Error", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.clearError() } }
        )) {
            Button("Dismiss", role: .cancel) {
                model.clearError()
            }
        } message: {
            Text(model.errorMessage ?? "Unknown error")
        }
        .sheet(isPresented: $model.showingCLIPicker) {
            CLIPickerView(
                onSelect: { path in
                    Task {
                        await model.addProtectedToolAtPath(path)
                    }
                },
                onCancel: {
                    model.showingCLIPicker = false
                }
            )
        }
        .overlay {
            if model.isLoading {
                ProgressView("Loading policy state…")
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
            }
        }
        .background(WindowConfigurationView())
    }

    private var sidebar: some View {
        List(selection: $model.selectedToolID) {
            Section {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Protection")
                        .font(.headline)

                    Toggle(isOn: Binding(
                        get: { model.protectionEnabled },
                        set: { newValue in
                            Task {
                                await model.setProtectionEnabled(newValue)
                            }
                        }
                    )) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(model.protectionEnabled ? "Enabled" : "Disabled")
                                .font(.title3.weight(.semibold))
                            Text(model.protectionEnabled ? "Rules are enforced." : "Protection disabled.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.switch)

                    HStack(spacing: 6) {
                        Circle()
                            .fill(model.extensionStatus.isRunning ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(model.extensionStatus.isRunning ? "Enforcement active" : "Enforcement inactive")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Spacer()

                        Button(model.extensionStatus.isRunning ? "Active" : "Activate") {
                            model.activateExtension()
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        .disabled(model.extensionStatus.isRunning)
                    }

                    if case .failed(let msg) = model.extensionStatus {
                        Text(msg)
                            .font(.caption2)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Button {
                        Task {
                            await model.refresh()
                        }
                    } label: {
                        Label("Refresh Policy State", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.vertical, 8)
            }

            Section("Protected Tools") {
                ForEach(model.protectedTools) { tool in
                    HStack(spacing: 10) {
                        Image(systemName: "terminal")
                            .foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(model.toolDisplayName(tool))
                                .font(.body.weight(.semibold))
                            Text(tool.path)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .tag(tool.id)
                    .contextMenu {
                        Button("Remove Tool", role: .destructive) {
                            Task {
                                await model.removeProtectedTool(id: tool.id)
                            }
                        }
                    }
                }
                .onDelete { offsets in
                    for index in offsets {
                        let tool = model.protectedTools[index]
                        Task {
                            await model.removeProtectedTool(id: tool.id)
                        }
                    }
                }

                Button {
                    model.addProtectedTool()
                } label: {
                    Label("Add Protected Tool", systemImage: "plus")
                }
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 250, ideal: 250, max: 250)
        .safeAreaInset(edge: .bottom) {
            if model.isMutating {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Applying changes…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(.thinMaterial)
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        if let tool = model.selectedTool {
            toolDetail(tool)
        } else {
            ContentUnavailableView(
                "No Protected Tools",
                systemImage: "shield.slash",
                description: Text("Add a CLI executable to define which apps are allowed to invoke it.")
            )
        }
    }

    private func toolDetail(_ tool: ProtectedTool) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header(for: tool)
                allowedApps(for: tool)
                eventFeed
            }
            .padding(28)
        }
        .background(
            LinearGradient(
                colors: [Color(nsColor: .windowBackgroundColor), Color.accentColor.opacity(0.08)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
    }

    private func header(for tool: ProtectedTool) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 10) {
                Text(model.toolDisplayName(tool))
                    .font(.largeTitle.weight(.bold))
                Text(tool.path)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)

                HStack(spacing: 12) {
                    StatPill(title: "Allowlisted Apps", value: "\(model.selectedToolAllowedCallers.count)", tint: .blue)
                    StatPill(title: "Recent Decisions", value: "\(model.events.prefix(20).count)", tint: .orange)
                    StatPill(title: "Protection", value: model.protectionEnabled ? "On" : "Off", tint: model.protectionEnabled ? .green : .gray)
                }
            }

            Spacer()

            Button(role: .destructive) {
                Task {
                    await model.removeProtectedTool(id: tool.id)
                }
            } label: {
                Label("Remove Tool", systemImage: "trash")
            }
            .buttonStyle(.bordered)
        }
    }

    private func allowedApps(for tool: ProtectedTool) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Allowed Apps")
                        .font(.title2.weight(.semibold))
                    Text("Only these apps or executables may invoke this protected tool.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    Task {
                        await model.addAllowedCaller(for: tool.id)
                    }
                } label: {
                    Label("Add Allowed App", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
            }

            if model.selectedToolAllowedCallers.isEmpty {
                ContentUnavailableView(
                    "No Allowed Apps",
                    systemImage: "app.badge",
                    description: Text("Add the apps that should be able to launch this tool without being blocked.")
                )
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
            } else {
                VStack(spacing: 12) {
                    ForEach(model.selectedToolAllowedCallers) { caller in
                        HStack(alignment: .top, spacing: 14) {
                            Image(systemName: "app.connected.to.app.below.fill")
                                .font(.title3)
                                .foregroundStyle(.blue)
                                .frame(width: 26)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(model.callerDisplayName(caller))
                                    .font(.headline)
                                Text(model.callerDetail(caller))
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }

                            Spacer()

                            Button(role: .destructive) {
                                Task {
                                    await model.removeAllowedCaller(id: caller.id)
                                }
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                        }
                        .padding(16)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
                    }
                }
            }
        }
    }

    private var eventFeed: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recent Activity")
                .font(.title2.weight(.semibold))

            if model.events.isEmpty {
                ContentUnavailableView(
                    "No Recent Decisions",
                    systemImage: "clock.badge.xmark",
                    description: Text("Allow and block decisions will appear here once GuardDog evaluates protected tool launches.")
                )
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20))
            } else {
                VStack(spacing: 12) {
                    ForEach(model.events.prefix(20)) { event in
                        HStack(alignment: .top, spacing: 14) {
                            Circle()
                                .fill(event.decision == .allow ? Color.green : Color.red)
                                .frame(width: 12, height: 12)
                                .padding(.top, 6)

                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(model.eventTitle(event))
                                        .font(.headline)
                                    Spacer()
                                    Text(Formatting.format(event.timestamp))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Text(model.eventSubtitle(event))
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                        .padding(16)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
                    }
                }
            }
        }
    }
}

private struct WindowConfigurationView: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        configureWindow(for: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        configureWindow(for: nsView)
    }

    private func configureWindow(for view: NSView) {
        DispatchQueue.main.async {
            view.window?.isMovableByWindowBackground = false
        }
    }
}

private struct StatPill: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased())
                .font(.caption2.weight(.bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.headline.weight(.semibold))
                .foregroundStyle(tint)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(tint.opacity(0.10), in: Capsule())
    }
}
