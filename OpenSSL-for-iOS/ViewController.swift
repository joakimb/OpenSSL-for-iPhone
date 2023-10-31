

import UIKit

class ViewController: UIViewController {
    

    
    @IBOutlet weak var outputLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.title = "OpenSSL-for-iOS"
        
//        let p256: ShamirP256 = ShamirP256()
        
//        let order: OpaquePointer =  p256.get0Order()
//        //let order  =  UnsafePointer<BIGNUM>(p256.get0Order())
//        P256.print(order)
        
        
        
        
        let output = PVSSWrapper.functionalityTest("")
        PVSSWrapper.performanceTest()
        outputLabel.text = output
    }
    
}
