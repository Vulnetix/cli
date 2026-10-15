import SwiftUI
import UIKit

struct LegacyWebView: UIViewRepresentable {
    let html: String

~>    func makeUIView(context: Context) -> UIWebView {
        let view = UIWebView()
        view.loadHTMLString(html, baseURL: nil)
        return view
    }

    func updateUIView(_ uiView: UIWebView, context: Context) {}
}
