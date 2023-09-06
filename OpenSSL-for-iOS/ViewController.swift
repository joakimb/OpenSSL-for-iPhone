

import UIKit

class ViewController: UIViewController {
    

    
    @IBOutlet weak var outputLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.title = "OpenSSL-for-iOS"
        
        let p256: P256 = P256()
        
        let order: OpaquePointer =  p256.get0Order()
        P256.print(order)
        
        
        
        var output = P256.test("")
        outputLabel.text = output
    }
    
}
