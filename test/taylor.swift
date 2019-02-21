import Foundation

public class Taylor: NSObject {
    @objc public var mood: String

    public override init() {
        self.mood = "creative"
    }

    public func saySomething() -> String {
        return "I am feeling \(mood)"
    }
}
