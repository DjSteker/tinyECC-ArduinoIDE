/*
 * tinyECC demo para Arduino
 * Cifra, descifra, firma y verifica un mensaje usando ECC sobre GF(991)
 */

//ls -l /dev/ttyACM*
//# Ver a quién pertenece
//stat /dev/ttyACM0
// sudo chmod 666 /dev/ttyACM0

#include "tinyECC.hpp"

tinyECC ecc;

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    ; /* Esperar conexión serial */
  }

  Serial.println(F("=== tinyECC Demo en Arduino ==="));
  Serial.print(F("Curva: y^2 = x^3 + "));
  Serial.print(ecc.a);
  Serial.print(F("x + "));
  Serial.print(ecc.b);
  Serial.print(F(" (mod "));
  Serial.print(ecc.p);
  Serial.println(F(")"));

  /* -------------------------------------------------------
     * 1. Cifrar y descifrar
     * ------------------------------------------------------- */
  Serial.println(F("\n--- Cifrado ---"));

  ecc.plaintext = "Hello World!";
  Serial.print(F("Original:  "));
  Serial.println(ecc.plaintext);

  ecc.encrypt();
  Serial.print(F("Cifrado:   "));
  Serial.println(ecc.ciphertext);

  ecc.plaintext = "";
  ecc.decrypt();
  Serial.print(F("Descifrado:"));
  Serial.println(ecc.plaintext);

  /* Comprobación */
  if (ecc.plaintext == "Hello World!") {
    Serial.println(F("OK: el descifrado coincide."));
  } else {
    Serial.println(F("ERROR: el descifrado no coincide."));
  }

  /* -------------------------------------------------------
     * 2. Firma digital
     * ------------------------------------------------------- */
  Serial.println(F("\n--- Firma digital ---"));

  ecc.plaintext = "Hola Arduino";
  ecc.encrypt(); /* genera hash m interno */

  ecc.genSig();
  Serial.print(F("Firma (r,s): ("));
  Serial.print(ecc.Sig[0]);
  Serial.print(F(", "));
  Serial.print(ecc.Sig[1]);
  Serial.println(F(")"));

  bool valida = ecc.verifySig();
  Serial.print(F("Verificacion: "));
  Serial.println(valida ? F("VALIDA") : F("INVALIDA"));

  /* -------------------------------------------------------
     * 3. Alterar la firma y verificar de nuevo
     * ------------------------------------------------------- */
  Serial.println(F("\n--- Verificacion con firma alterada ---"));

  ecc.Sig[1] = ecc.Sig[1] + 1; /* modificar s */

  bool alterada = ecc.verifySig();
  Serial.print(F("Verificacion alterada: "));
  Serial.println(alterada ? F("VALIDA (inesperado)") : F("INVALIDA (esperado)"));

  Serial.println(F("\n=== Fin del demo ==="));
}

void loop() {
  /* Nada que hacer en loop */
}
