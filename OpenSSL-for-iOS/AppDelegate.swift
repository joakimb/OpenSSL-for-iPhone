//
//  AppDelegate.swift
//  OpenSSL-for-iOS
//
//

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        self.window = UIWindow(frame: UIScreen.main.bounds)
        
        #if os(tvOS)
            self.window?.rootViewController = ViewController(nibName: "ViewController~tv", bundle:  nil)
        #else
            let navigationController = UINavigationController(rootViewController: ViewController())
            navigationController.navigationBar.isTranslucent = false
            self.window?.rootViewController = navigationController
        #endif
        
        self.window?.makeKeyAndVisible()
        return true
    }

}

