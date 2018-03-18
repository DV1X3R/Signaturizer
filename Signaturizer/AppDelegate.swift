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
    
    @IBOutlet weak var StuffSelectorPUB: NSPopUpButton!
    @IBOutlet weak var DataTF: NSTextField!
    @IBOutlet weak var StuffResultTF: NSTextField!
    @IBOutlet weak var SignatureTF: NSTextField!
    @IBOutlet weak var PassphraseSTF: NSSecureTextField!
    @IBOutlet var PrivateKeyTV: NSTextView!
    @IBOutlet var PublicKeyTV: NSTextView!
    
    func generateRsaKeys() -> (Data, Data) {
        // Create public and private RSA keys in DER format
        let (privateKey, publicKey) = try! CC.RSA.generateKeyPair(2048)
        
        // Convert them to PEM format
        let privateKeyPEM = SwKeyConvert.PrivateKey.derToPKCS1PEM(privateKey)
        let publicKeyPEM = SwKeyConvert.PublicKey.derToPKCS8PEM(publicKey)
        
        PrivateKeyTV.string = privateKeyPEM
        PublicKeyTV.string = publicKeyPEM
        
        return (privateKey, publicKey)
    }
    
    @IBAction func cryptPrivateKey(_ sender: Any) {
        // Encrypt, decrypt the private key (OpenSSL compatible)
        if let s = try? SwKeyConvert.PrivateKey.encryptPEM(PrivateKeyTV.string, passphrase: PassphraseSTF.stringValue, mode: .aes256CBC)
        { PrivateKeyTV.string = s }
        else if let s = try? SwKeyConvert.PrivateKey.decryptPEM(PrivateKeyTV.string, passphrase: PassphraseSTF.stringValue)
        { PrivateKeyTV.string = s }
        else {
            showAlert(message: "Wrong passphrase", information: "Please check the passphrase"
                , style: NSAlert.Style.critical, btn1Str: "OK", btn2Str: "")
        }
    }
    
    func getPrivateKeyDER() -> Data? {
        // Read from string with PEM data
        if let privateKeyDER = try? SwKeyConvert.PrivateKey.pemToPKCS1DER(PrivateKeyTV.string)
        { return privateKeyDER }
        else {
            if showAlert(message: "Private Key is invalid", information: "Please check the Private Key or generate a new keypair"
                , style: NSAlert.Style.critical, btn1Str: "Generate a new keypair", btn2Str: "Cancel") == true
            { return generateRsaKeys().0 }
            else { return nil }
        }
    }
    
    func getPublicKeyDER() -> Data? {
        // Read from string with PEM data
        if let publicKeyDER = try? SwKeyConvert.PublicKey.pemToPKCS1DER(PublicKeyTV.string)
            { return publicKeyDER }
        else {
            if showAlert(message: "Public Key is invalid", information: "Please check the Public Key or generate a new keypair"
                , style: NSAlert.Style.critical, btn1Str: "Generate a new keypair", btn2Str: "Cancel") == true
            { return generateRsaKeys().1 }
            else { return nil }
        }
    }
    
    func getStuffData(base64: Bool, canBeEmpty: Bool) -> Data? {
        if !canBeEmpty && DataTF.stringValue == ""
        {
            showAlert(message: "Data is empty", information: "Please enter a valid string into the \"Data\" section"
                , style: NSAlert.Style.critical, btn1Str: "OK", btn2Str: "")
            return nil
        }
        
        if base64 { return Data(base64Encoded: DataTF.stringValue) }
        else { return DataTF.stringValue.data(using: .utf8) }
    }
    
    func getSignatureData() -> Data? {
        return Data(base64Encoded: SignatureTF.stringValue)
    }
    
    @IBAction func doStuff(_ sender: Any) {
        switch StuffSelectorPUB.title {
            
        case "RSA Encrypt":
            if let publicKeyDER = getPublicKeyDER() {
                if let stuffData = getStuffData(base64: false, canBeEmpty: false) {
                    // Encrypt data with RSA
                    let encodedData = try! CC.RSA.encrypt(stuffData, derKey: publicKeyDER, tag: Data(), padding: .oaep, digest: .sha256)
                    StuffResultTF.stringValue = encodedData.base64EncodedString()
                }
            }
            
        case "RSA Decrypt":
            if let privateKeyDER = getPrivateKeyDER() {
                if let stuffData = getStuffData(base64: true, canBeEmpty: false) {
                    // Decrypt data with RSA
                    if let decodedData = try? CC.RSA.decrypt(stuffData, derKey: privateKeyDER, tag: Data(), padding: .oaep, digest: .sha256) {
                        StuffResultTF.stringValue = String.init(data: decodedData.0, encoding: .utf8)!
                    }
                    else {
                        showAlert(message: "Unable to decrypt", information: "Unable to decrypt data with Private Key"
                            , style: NSAlert.Style.critical, btn1Str: "OK", btn2Str: "")
                    }
                }
                else {
                    showAlert(message: "Data is invalid", information: "Please check the encrypted data"
                        , style: NSAlert.Style.critical, btn1Str: "OK", btn2Str: "")
                }
            }
            
        case "Sign Data":
            if let privateKeyDER = getPrivateKeyDER() {
                if let stuffData = getStuffData(base64: false, canBeEmpty: true) {
                    // Sign data with RSA
                    let sign = try? CC.RSA.sign(stuffData, derKey: privateKeyDER, padding: .pss, digest: .sha256, saltLen: 16)
                    SignatureTF.stringValue = (sign?.base64EncodedString())!
                }
            }
            
        case "Verify Signature":
            if let publicKeyDER = getPublicKeyDER() {
                if let stuffData = getStuffData(base64: false, canBeEmpty: true) {
                    if let signatureData = getSignatureData() {
                        // Verify data with RSA
                        let verified = try? CC.RSA.verify(stuffData, derKey: publicKeyDER, padding: .pss, digest: .sha256, saltLen: 16, signedData: signatureData)
                        if verified == true {
                            SignatureTF.backgroundColor = NSColor.green
                            DispatchQueue.global(qos: .background).async {
                                sleep(2)
                                DispatchQueue.main.async {
                                    self.SignatureTF.backgroundColor = nil
                                }
                            }
                        }
                        else {
                            SignatureTF.backgroundColor = NSColor.red
                            DispatchQueue.global(qos: .background).async {
                                sleep(2)
                                DispatchQueue.main.async {
                                    self.SignatureTF.backgroundColor = nil
                                }
                            }
                        }
                    }
                }
            }
            
        case "SHA256": StuffResultTF.stringValue = CC.digest(getStuffData(base64: false, canBeEmpty: true)!, alg: .sha256).hexadecimalString()
        case "MD5": StuffResultTF.stringValue = CC.digest(getStuffData(base64: false, canBeEmpty: true)!, alg: .md5).hexadecimalString()
        case "Base64": StuffResultTF.stringValue = (getStuffData(base64: false, canBeEmpty: true)?.base64EncodedString())!
        case "Base64 Decode":
            if let dBase64 = getStuffData(base64: true, canBeEmpty: false) {
                if let sBase64 = String(data: dBase64, encoding: .utf8) {
                    StuffResultTF.stringValue = sBase64
                }
            }
            else {
                showAlert(message: "Unable to decode", information: "Unable to decode data using Base64"
                    , style: NSAlert.Style.critical, btn1Str: "OK", btn2Str: "")
            }
            
        case "UUID Generator": StuffResultTF.stringValue = UUID().uuidString
        default: break
        }
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
    
    func showAlert(message: String, information: String, style: NSAlert.Style, btn1Str: String, btn2Str: String ) -> Bool {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = information
        alert.alertStyle = style
        alert.addButton(withTitle: btn1Str)
        alert.addButton(withTitle: btn2Str)
        return alert.runModal() == .alertFirstButtonReturn
    }

}

