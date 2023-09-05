

import UIKit

class ViewController: UIViewController {
    

    
    @IBOutlet weak var outputLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.title = "OpenSSL-for-iOS"
        var output = P256.test("")
        outputLabel.text = output
    }
    
}
