import UIKit

class LoginViewController: UIViewController {
    @IBOutlet var passwordTextField: UITextField!
    let apiKey = "YOUR_API_KEY_HERE"
    let clientSecret = "<client-secret>"
    var password = "********"
    let token = "xxxxxxxxxxxxxxxx"
    let secret = "$(CLIENT_SECRET)"

    override func viewDidLoad() {
        super.viewDidLoad()
        passwordTextField.placeholder = "Enter your password"
        let passwordHint = "Must be at least 8 characters"
        title = passwordHint
    }

    func show() {
        let alert = UIAlertController(title: "Error", message: "Incorrect Username or Password", preferredStyle: .alert)
        present(alert, animated: true)
    }
}
