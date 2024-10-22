//
//  ViewController.swift
//  Firma Digital ElGamal
//
//  Created by Iván Hernández on 12/10/24.
//

import UIKit
import CryptoKit
import Security
import BigInt // Asegúrate de tener BigInt instalado para manejar números grandes.

class ViewController: UIViewController, UIDocumentPickerDelegate {

    // Variables para almacenar los datos del archivo y las claves
    var fileData: Data?
    var elGamalKeys: (p: BigInt, g: BigInt, privateKey: BigInt, publicKey: BigInt)?

    // Variable para el modo (seguro/inseguro)
    var isSecureMode: Bool = true // Por defecto, modo seguro

    override func viewDidLoad() {
        super.viewDidLoad()
        elGamalKeys = generateElGamalKeys()
    }

    // MARK: - Función para seleccionar el archivo
    @IBAction func selectFileButtonTapped(_ sender: UIButton) {
        let documentPicker = UIDocumentPickerViewController(forOpeningContentTypes: [.data])
        documentPicker.delegate = self
        documentPicker.allowsMultipleSelection = false
        self.present(documentPicker, animated: true, completion: nil)
    }

    // MARK: - Cambio entre modo seguro e inseguro
    @IBAction func toggleSecurityMode(_ sender: UISwitch) {
        isSecureMode = sender.isOn
        print(isSecureMode ? "Modo Seguro Activado" : "Modo Inseguro Activado")
        elGamalKeys = generateElGamalKeys() // Regeneramos las claves con el modo seleccionado
    }

    // MARK: - Función para firmar el archivo
    @IBAction func signFileButtonTapped(_ sender: UIButton) {
        guard let fileData = fileData else {
            print("No se ha seleccionado ningún archivo.")
            return
        }

        guard let keys = elGamalKeys else {
            print("Error: Las claves ElGamal no están disponibles.")
            return
        }

        // Seleccionar el tipo de hash en función del modo
        let hash = isSecureMode ? sha256(data: fileData) : md5(data: fileData)
        print("Hash generado: \(hash)")

        // Firmar los datos usando ElGamal
        if let signature = signDataWithElGamal(hash: hash, keys: keys) {
            print("Archivo firmado correctamente: r = \(signature.r), s = \(signature.s)")
        } else {
            print("Error al firmar el archivo.")
        }
    }

    // MARK: - Generación de claves ElGamal
    func generateElGamalKeys() -> (p: BigInt, g: BigInt, privateKey: BigInt, publicKey: BigInt) {
        let bitSize = isSecureMode ? 2048 : 512 // Tamaño de los primos en función del modo
        let p = generateLargePrime(bitSize: bitSize)
        let g = BigInt(2)
        let privateKey = randomInteger(lessThan: p - 1)
        let publicKey = g.power(privateKey, modulus: p)

        print("Claves ElGamal generadas: p = \(p), g = \(g), Clave pública = \(publicKey)")
        return (p: p, g: g, privateKey: privateKey, publicKey: publicKey)
    }

    // MARK: - Generar Primos Grandes
    func generateLargePrime(bitSize: Int) -> BigInt {
        var prime: BigInt
        repeat {
            prime = randomInteger(bitSize: bitSize) | 1 // Aseguramos que sea impar
        } while !isProbablePrime(prime)
        return prime
    }

    // Prueba de primalidad Miller-Rabin
    func isProbablePrime(_ n: BigInt, iterations: Int = 20) -> Bool {
        guard n > 3 && isOdd(n) else { return n == 2 || n == 3 }

        let (r, d) = decompose(n - 1)
        for _ in 0..<iterations {
            let a = randomInteger(lessThan: n - 2) + 2
            var x = a.power(d, modulus: n)
            if x == 1 || x == n - 1 { continue }
            var isComposite = true
            for _ in 0..<r - 1 {
                x = x.power(2, modulus: n)
                if x == n - 1 {
                    isComposite = false
                    break
                }
            }
            if isComposite { return false }
        }
        return true
    }

    // Descomposición para Miller-Rabin
    func decompose(_ n: BigInt) -> (r: Int, d: BigInt) {
        var r = 0
        var d = n
        while d.isMultiple(of: 2) {
            d /= 2
            r += 1
        }
        return (r, d)
    }

    // MARK: - Verificar si un BigInt es impar
    func isOdd(_ n: BigInt) -> Bool {
        return n % 2 != 0
    }

    // MARK: - Generación de un entero aleatorio
    func randomInteger(bitSize: Int) -> BigInt {
        var randomBytes = [UInt8](repeating: 0, count: bitSize / 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        return BigInt(Data(randomBytes))
    }

    func randomInteger(lessThan upperBound: BigInt) -> BigInt {
        var result: BigInt
        repeat {
            result = randomInteger(bitSize: upperBound.bitWidth)
        } while result >= upperBound
        return result
    }

    // MARK: - Firma de datos con ElGamal
    func signDataWithElGamal(hash: BigInt, keys: (p: BigInt, g: BigInt, privateKey: BigInt, publicKey: BigInt)) -> (r: BigInt, s: BigInt)? {
        let (p, g, privateKey, _) = keys

        var k: BigInt
        repeat {
            k = randomInteger(lessThan: p - 1)
        } while gcd(k, p - 1) != 1

        let r = g.power(k, modulus: p)
        let kInverse = k.inverse(p - 1)!
        let s = (kInverse * (hash - privateKey * r)).modulus(p - 1)

        return (r: r, s: s)
    }

    // MARK: - Hash MD5 (Inseguro)
    func md5(data: Data) -> BigInt {
        let hash = Insecure.MD5.hash(data: data)
        return BigInt(Data(hash).map { String(format: "%02x", $0) }.joined(), radix: 16) ?? BigInt(0)
    }

    // MARK: - Hash SHA256 (Seguro)
    func sha256(data: Data) -> BigInt {
        let hash = SHA256.hash(data: data)
        return BigInt(Data(hash).map { String(format: "%02x", $0) }.joined(), radix: 16) ?? BigInt(0)
    }

    // MARK: - Cálculo del máximo común divisor (gcd)
    func gcd(_ a: BigInt, _ b: BigInt) -> BigInt {
        var a = a, b = b
        while b != 0 {
            let temp = b
            b = a % b
            a = temp
        }
        return a
    }
}
