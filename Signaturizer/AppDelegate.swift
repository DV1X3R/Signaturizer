//
//  AppDelegate.swift
//  Signaturizer
//
//  Created by DV1X3R on 06/03/2018.
//  Copyright © 2018 DV1X3R. All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet weak var window: NSWindow!

    @IBOutlet weak var tfHash: NSTextFieldCell!
    @IBOutlet weak var slHash: NSPopUpButton!
    
    @IBAction func updateTfHash(_ sender: Any) {
        let sData = tfHash.stringValue.data(using: .utf8)
        var sHash : String = ""
        
        switch slHash.title {
        case "SHA256":
            sHash = CC.digest(sData!, alg: .sha256).hexadecimalString()
            
        case "MD5":
            sHash = CC.digest(sData!, alg: .md5).hexadecimalString()
            
        default:
            break
        }
        
        tfHash.stringValue = sHash
    }
    
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
    

}

