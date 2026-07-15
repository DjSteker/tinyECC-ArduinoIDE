/*
 * tinyECC.hpp
 *
 *  Created on: 15 jul 2026
 *      Author: usuario001
 */

#ifndef TINYECC_HPP_
#define TINYECC_HPP_

#ifdef ARDUINO
  #include <Arduino.h>
#else
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdint>
#endif

#include "tinyECC_mapping_table.hpp"

/* ---------- Tipo de texto portable ---------- */
#ifdef ARDUINO
  typedef String ECCString;
#else
typedef std::string ECCString;
#endif

class tinyECC {
public:
	// Curva expuesta públicamente
	int a, b, p;

	// Datos de entrada/salida
	ECCString plaintext;
	ECCString ciphertext;
	int Sig[2];

	// Claves accesibles para debug/inspección (public ahora)
	int PrivKey;
	int PubKey[2];
	int Pbase[2];
	int m;  // Hash interno para debugging

	tinyECC();
	void encrypt();
	void genSig();
	void decrypt();
	bool verifySig();

	/* Configuración de curva */
	void setCurve(int aVal, int bVal, int pVal);
	void setKeys(int privKey, int pubX, int pubY, int baseX, int baseY);

protected:
	int PubSer[2];
	int PbaseSer[2];
	int TempArr[2];
	int E[4];
	int P[4];

	void encode(int msg[2], int pb[2], int pbase[2]);
	void sclr_mult(int k, int pt[2]);
	void add(int pt1[2], int pt2[2]);
	int isPAI(int *point);
	long int inverse(long int num);
	int inverse1(int num);
	void decode();

private:
	const int* alphaTable();
	int alphaAt(int index);
	void eccSrand();
};

#endif /* TINYECC_HPP_ */
