//
//  ViewController.swift
//  Firma Digital
//
//  Created by Iván Hernández on 12/10/24.
//

import UIKit
import Security
import CryptoKit

import UIKit
import Security
import CryptoKit

class ViewController: UIViewController {
    
    // Variables para almacenar los datos del archivo
    var fileData: Data?
    
    // MARK: - Función para seleccionar el archivo
    @IBAction func selectFileButtonTapped(_ sender: UIButton) {
        let documentPicker = UIDocumentPickerViewController(forOpeningContentTypes: [.data])
        documentPicker.delegate = self
        documentPicker.allowsMultipleSelection = false
        self.present(documentPicker, animated: true, completion: nil)
    }
    
    // MARK: - Función para firmar el archivo con RSA
    @IBAction func signFileButtonTapped(_ sender: UIButton) {
        guard let fileData = fileData else {
            print("No se ha seleccionado ningún archivo.")
            return
        }
        
        // Generar o cargar la clave RSA privada
        guard let privateKey = generateRSAKey()?.privateKey else {
            print("Error al generar o cargar la clave privada RSA.")
            return
        }
        
        // Firmar los datos del archivo con la clave privada
        if let signature = signDataWithRSA(data: fileData, privateKey: privateKey) {
            print("Archivo firmado correctamente: \(signature.base64EncodedString())")
        } else {
            print("Error al firmar el archivo.")
        }
    }
    
    // MARK: - Función para generar una clave RSA
    func generateRSAKey() -> (privateKey: SecKey, publicKey: SecKey)? {
        let tag = "com.example.keys.mykey".data(using: .utf8)!
        
        let privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag
        ]
        
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: privateKeyAttributes
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
            print("Error al generar la clave privada RSA: \(error!.takeRetainedValue())")
            return nil
        }
        
        // Obtener la clave pública a partir de la clave privada generada
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print("Error al obtener la clave pública RSA.")
            return nil
        }
        
        return (privateKey: privateKey, publicKey: publicKey)
    }
    
    // MARK: - Función para firmar los datos del archivo usando la clave privada RSA
    func signDataWithRSA(data: Data, privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        
        let signature = SecKeyCreateSignature(privateKey,
                                              .rsaSignatureMessagePKCS1v15SHA256,
                                              data as CFData,
                                              &error)
        
        if let error = error {
            print("Error al firmar los datos: \(error.takeRetainedValue() as Error)")
            return nil
        }
        
        return signature as Data?
    }
}

// MARK: - Extensión para manejar la selección de archivos
extension ViewController: UIDocumentPickerDelegate {
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let selectedFileURL = urls.first else { return }
        
        do {
            fileData = try Data(contentsOf: selectedFileURL)
            print("Archivo cargado: \(selectedFileURL.lastPathComponent)")
        } catch {
            print("Error al cargar el archivo: \(error)")
        }
    }
    
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        print("Selección de archivo cancelada.")
    }
}
