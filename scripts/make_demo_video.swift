import AVFoundation
import AppKit
import CoreGraphics
import Foundation

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "submission/findevil-demo.mp4"
let outputURL = URL(fileURLWithPath: output)
try? FileManager.default.removeItem(at: outputURL)

let width = 1280
let height = 720
let fps: Int32 = 30
let durationSeconds = 60

let writer = try AVAssetWriter(outputURL: outputURL, fileType: .mp4)
let settings: [String: Any] = [
    AVVideoCodecKey: AVVideoCodecType.h264,
    AVVideoWidthKey: width,
    AVVideoHeightKey: height
]
let input = AVAssetWriterInput(mediaType: .video, outputSettings: settings)
input.expectsMediaDataInRealTime = false
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
    kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_32ARGB),
    kCVPixelBufferWidthKey as String: width,
    kCVPixelBufferHeightKey as String: height
])

writer.add(input)
writer.startWriting()
writer.startSession(atSourceTime: .zero)

func drawText(_ text: String, _ rect: CGRect, _ size: CGFloat, _ color: NSColor, _ weight: NSFont.Weight = .regular) {
    let paragraph = NSMutableParagraphStyle()
    paragraph.lineSpacing = 6
    let attrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: size, weight: weight),
        .foregroundColor: color,
        .paragraphStyle: paragraph
    ]
    text.draw(in: rect, withAttributes: attrs)
}

func drawMono(_ text: String, _ rect: CGRect, _ size: CGFloat, _ color: NSColor) {
    let paragraph = NSMutableParagraphStyle()
    paragraph.lineSpacing = 5
    let attrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.monospacedSystemFont(ofSize: size, weight: .regular),
        .foregroundColor: color,
        .paragraphStyle: paragraph
    ]
    text.draw(in: rect, withAttributes: attrs)
}

let slides: [(String, String, String)] = [
    (
        "FindEvil Triage Agent",
        "Read-only DFIR triage with evidence hashing, artifact correlation, risk scoring, and visible self-correction.",
        "$ python3 src/find_evil_agent.py data/case-001 --out artifacts\n\n[detector] auth: repeated SSH failures\n[detector] process: suspicious curl-to-shell\n[detector] network: unusual outbound port\n[detector] persistence: cron artifact changed\n[detector] dns: suspicious staging lookup"
    ),
    (
        "Evidence Inventory",
        "Every source artifact is hashed before analysis. The agent treats evidence as read-only input.",
        "auth.log           sha256: 05a97d7c...\ncrontab.txt       sha256: 53a91f54...\ndns.log           sha256: aa66aeee...\nfile_timeline.csv sha256: 78564068...\nnetwork.json      sha256: 92fd32cb...\nprocesses.json    sha256: 648a9637..."
    ),
    (
        "Supported Findings",
        "The final report contains 8 supported findings, sorted by risk score and tied to cited artifacts.",
        "98 high   Failed logins followed by success\n93 high   Process-to-network correlation\n72 medium Repeated SSH failures\n65 medium Suspicious DNS lookup\n60 medium Suspicious command line\n60 medium Cron artifact changed\n59 medium Unusual outbound port\n59 medium Suspicious scheduled task"
    ),
    (
        "Self-Correction Sequence",
        "The agent records candidate claims, then removes or downgrades claims that do not meet evidence policy.",
        "[candidate] Possible malware persistence\n[action] removed\n[reason] No cited artifact supported the claim.\n\n[candidate] Suspicious scheduled task\n[action] downgraded high -> medium\n[reason] High severity requires at least two evidence references."
    ),
    (
        "MCP-Ready Tool Surface",
        "The prototype exposes inventory and triage operations through a JSON-RPC stdio interface for future SIFT / Protocol SIFT integration.",
        "$ printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\\n' | python3 src/mcp_server.py\n\n- inventory_case\n- run_triage\n\nOutputs: artifacts/report.json and artifacts/execution-log.jsonl"
    ),
    (
        "Architecture Guardrails",
        "Custom MCP Server pattern: read-only evidence, hash inventory, detector passes, correlation, self-correction, final report.",
        "Evidence Bundle -> SHA-256 Inventory -> Detector Passes\n     -> Cross-Artifact Correlation -> Self-Correction\n     -> Supported Report + JSONL Execution Log\n\nFinal claims require cited artifacts. Missing support is logged, not hidden."
    )
]

func makePixelBuffer(second: Int) -> CVPixelBuffer {
    var buffer: CVPixelBuffer?
    CVPixelBufferCreate(kCFAllocatorDefault, width, height, kCVPixelFormatType_32ARGB, nil, &buffer)
    guard let pixelBuffer = buffer else { fatalError("Unable to create pixel buffer") }
    CVPixelBufferLockBaseAddress(pixelBuffer, [])
    let context = CGContext(
        data: CVPixelBufferGetBaseAddress(pixelBuffer),
        width: width,
        height: height,
        bitsPerComponent: 8,
        bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer),
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue
    )!

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    NSColor(calibratedRed: 0.04, green: 0.06, blue: 0.09, alpha: 1).setFill()
    CGRect(x: 0, y: 0, width: width, height: height).fill()
    NSColor(calibratedRed: 0.08, green: 0.12, blue: 0.18, alpha: 1).setFill()
    CGRect(x: 54, y: 82, width: 1172, height: 560).fill()
    NSColor(calibratedRed: 0.13, green: 0.22, blue: 0.35, alpha: 1).setFill()
    CGRect(x: 54, y: 82, width: 1172, height: 58).fill()

    let slide = slides[min(second / 10, slides.count - 1)]
    drawText(slide.0, CGRect(x: 82, y: 103, width: 700, height: 44), 28, .white, .bold)
    drawText("FIND EVIL demo", CGRect(x: 980, y: 107, width: 210, height: 32), 18, NSColor(calibratedRed: 0.70, green: 0.82, blue: 1, alpha: 1), .semibold)
    drawText(slide.1, CGRect(x: 86, y: 172, width: 1040, height: 92), 22, NSColor(calibratedRed: 0.82, green: 0.89, blue: 0.98, alpha: 1), .regular)
    drawMono(slide.2, CGRect(x: 94, y: 292, width: 1040, height: 292), 24, NSColor(calibratedRed: 0.75, green: 0.95, blue: 0.78, alpha: 1))
    drawText("Generated demo asset for Devpost submission. No real patient, customer, or third-party data is used.", CGRect(x: 86, y: 608, width: 980, height: 32), 16, NSColor(calibratedRed: 0.70, green: 0.76, blue: 0.84, alpha: 1), .regular)
    drawText("\(second + 1)s / \(durationSeconds)s", CGRect(x: 1110, y: 608, width: 90, height: 32), 16, NSColor(calibratedRed: 0.70, green: 0.76, blue: 0.84, alpha: 1), .regular)
    NSGraphicsContext.restoreGraphicsState()
    CVPixelBufferUnlockBaseAddress(pixelBuffer, [])
    return pixelBuffer
}

var frame: Int64 = 0
let totalFrames = durationSeconds * Int(fps)
while frame < Int64(totalFrames) {
    while !input.isReadyForMoreMediaData {
        Thread.sleep(forTimeInterval: 0.01)
    }
    let second = Int(frame / Int64(fps))
    let buffer = makePixelBuffer(second: second)
    let time = CMTime(value: frame, timescale: fps)
    adaptor.append(buffer, withPresentationTime: time)
    frame += 1
}

input.markAsFinished()
writer.finishWriting {
    exit(writer.status == .completed ? 0 : 1)
}
RunLoop.main.run()

