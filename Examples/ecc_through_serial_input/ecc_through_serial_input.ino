
// **********************************************************************************
// Author:    Shubham Annigeri	github.com/ShubhamAnnigeri
// co-Author: Sunit Raut   	    github.com/SunitRaut
// co-Author: DjSteker   	    github.com/DjSteker
// **********************************************************************************
// License
// **********************************************************************************
// This program is free software; you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will
// be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public
// License for more details.
//
// Licence can be viewed at
// http://www.gnu.org/licenses/gpl-3.0.txt
//
// Please maintain this license information along with authorship
// and copyright notices in any redistribution of this code
// **********************************************************************************
// This file: Generate Signature and verify signature for a plaintext string
// **********************************************************************************

/*
 * tinyECC - Comandos por Serial
 * Prefijos disponibles:
 *   E:<texto>     -> Encriptar texto
 *   D:<ciphertext>-> Desencriptar
 *   F:<mensaje>   -> Generar firma (F)
 *   V             -> Verificar última firma (verifica con m interno)
 *   P             -> Mostrar parámetros (P)
 *   S             -> Estado/Debug
 *
 * Ejemplos:
 *   E:Hola Mundo   -> cifra "Hola Mundo"
 *   D:C1,C2,C3,C4,... -> descifra el ciphertext
 *   F:Prueba      -> genera firma para "Prueba"
 */

//ls -l /dev/ttyACM*
//# Ver a quién pertenece
//stat /dev/ttyACM0
// sudo chmod 666 /dev/ttyACM0

#include "tinyECC.hpp"

tinyECC ecc;

#define SERIAL_BAUD 9600
#define RX_BUFFER_SIZE 256

char rxBuffer[RX_BUFFER_SIZE];
int rxIndex = 0;
bool commandReady = false;

void processCommand(const char* cmd);
void printHelp();
void printStatus();

void setup() {
  Serial.begin(SERIAL_BAUD);
  while (!Serial) {
    ;
  }

  Serial.println(F("=== tinyECC Command Line ==="));
  Serial.println(F("Comandos:"));
  Serial.println(F("  E:<texto>    -> Encriptar"));
  Serial.println(F("  D:<cipher>   -> Desencriptar"));
  Serial.println(F("  F:<texto>    -> Firmar"));
  Serial.println(F("  V            -> Verificar firma"));
  Serial.println(F("  P            -> Parámetros de curva"));
  Serial.println(F("  S            -> Estado/Debug"));
  Serial.println(F("  H            -> Ayuda"));
  Serial.println(F("--------------------------------"));

  printStatus();
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();

    if (c == '\n' || c == '\r') {
      if (rxIndex > 0) {
        rxBuffer[rxIndex] = '\0';
        commandReady = true;
      }
      rxIndex = 0;
      continue;
    }

    if (rxIndex < RX_BUFFER_SIZE - 1) {
      rxBuffer[rxIndex++] = c;
    }
  }

  if (commandReady) {
    processCommand(rxBuffer);
    commandReady = false;
    rxIndex = 0;
  }
}

void processCommand(const char* cmd) {
  Serial.print(F("> "));
  Serial.println(cmd);

  if (cmd[0] == '\0') {
    return;
  }

  char prefix = cmd[0];
  const char* arg = &cmd[1];

  if (arg[0] == ':') {
    arg++;
  }

  switch (prefix) {
    case 'E':
      {
        Serial.println(F("--- Encriptando ---"));
        ecc.plaintext = arg;
        Serial.print(F("Original:  "));
        Serial.println(ecc.plaintext);

        ecc.encrypt();
        Serial.print(F("Cifrado:   "));
        Serial.println(ecc.ciphertext);
        break;
      }

    case 'D':
      {
        Serial.println(F("--- Desencriptando ---"));
        ecc.ciphertext = arg;
        Serial.print(F("Cifrado:   "));
        Serial.println(ecc.ciphertext);

        ecc.plaintext = "";
        ecc.decrypt();
        Serial.print(F("Descifrado:"));
        Serial.println(ecc.plaintext);
        break;
      }

    case 'F':
      {
        Serial.println(F("--- Firmando ---"));
        ecc.plaintext = arg;
        Serial.print(F("Mensaje:   "));
        Serial.println(ecc.plaintext);

        ecc.encrypt();
        ecc.genSig();
        Serial.print(F("Firma (r,s): ("));
        Serial.print(ecc.Sig[0]);
        Serial.print(F(", "));
        Serial.print(ecc.Sig[1]);
        Serial.println(F(")"));
        break;
      }

    case 'V':
      {
        Serial.println(F("--- Verificando ---"));
        Serial.print(F("Firma: ("));
        Serial.print(ecc.Sig[0]);
        Serial.print(F(", "));
        Serial.print(ecc.Sig[1]);
        Serial.println(F(")"));

        bool valid = ecc.verifySig();
        Serial.print(F("Resultado: "));
        Serial.println(valid ? F("VALIDA") : F("INVALIDA"));
        break;
      }

    case 'P':
      {
        Serial.println(F("--- Parámetros de Curva ---"));
        Serial.print(F("Curva: y^2 = x^3 + "));
        Serial.print(ecc.a);
        Serial.print(F("x + "));
        Serial.print(ecc.b);
        Serial.print(F(" (mod "));
        Serial.print(ecc.p);
        Serial.println(F(")"));

        Serial.print(F("Base point: ("));
        Serial.print(ecc.Pbase[0]);
        Serial.print(F(", "));
        Serial.print(ecc.Pbase[1]);
        Serial.println(F(")"));

        Serial.print(F("Public key: ("));
        Serial.print(ecc.PubKey[0]);
        Serial.print(F(", "));
        Serial.print(ecc.PubKey[1]);
        Serial.println(F(")"));
        break;
      }

    case 'S':
      {
        printStatus();
        break;
      }

    case 'H':
      {
        printHelp();
        break;
      }

    default:
      Serial.println(F("Comando desconocido. Usa H para ayuda."));
      break;
  }

  Serial.println();
}

void printHelp() {
  Serial.println(F("Comandos:"));
  Serial.println(F("  E:<texto>      -> Encriptar texto"));
  Serial.println(F("  D:<cipher>     -> Desencriptar"));
  Serial.println(F("  F:<texto>      -> Firmar mensaje"));
  Serial.println(F("  V              -> Verificar firma"));
  Serial.println(F("  P              -> Parámetros de curva"));
  Serial.println(F("  S              -> Estado/Debug"));
  Serial.println(F("  H              -> Ayuda"));
}

void printStatus() {
  Serial.println(F("--- Estado ---"));
  Serial.print(F("Hash interno (m): "));
  Serial.println(ecc.m);

  Serial.print(F("Longitud plaintext: "));
  Serial.println(ecc.plaintext.length());

  Serial.print(F("Longitud ciphertext: "));
  Serial.println(ecc.ciphertext.length());

  Serial.print(F("Última firma: ("));
  Serial.print(ecc.Sig[0]);
  Serial.print(F(", "));
  Serial.print(ecc.Sig[1]);
  Serial.println(F(")"));
}

