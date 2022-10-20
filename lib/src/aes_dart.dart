// Copyright (c) 2022, Very Good Ventures
// https://verygood.ventures
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart';

/// encrypt data
Future<String> aesEncrypt(String plainText, String password) async {
  final iv = IV.fromSecureRandom(16);
  final salt = IV.fromSecureRandom(16).bytes;
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 1,
    bits: 512,
  );
  final newSecretKey = await pbkdf2.deriveKey(
    secretKey: SecretKey(ascii.encode(password)),
    nonce: salt,
  );
  final key = await newSecretKey.extractBytes();
  final encrypter = Encrypter(
    AES(
      Key(Uint8List.fromList(key.sublist(0, 32))),
      mode: AESMode.cbc,
    ),
  );
  final encrypted = encrypter.encrypt(plainText, iv: iv);
  final packaged = iv.bytes + salt + encrypted.bytes;
  return base64.encode(packaged);
}

/// decrypted data
Future<String> aesDecrypt(String input, String password) async {
  final unpackaged = base64.decode(input);
  final iv = IV(unpackaged.sublist(0, 16));
  final salt = unpackaged.sublist(16, 32);
  final data = unpackaged.sublist(32);
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 1,
    bits: 512,
  );
  final newSecretKey = await pbkdf2.deriveKey(
    secretKey: SecretKey(ascii.encode(password)),
    nonce: salt,
  );
  final key = await newSecretKey.extractBytes();
  final encrypter = Encrypter(
    AES(
      Key(Uint8List.fromList(key.sublist(0, 32))),
      mode: AESMode.cbc,
    ),
  );
  final encrypted = encrypter.decrypt(Encrypted(data), iv: iv);
  return encrypted;
}
