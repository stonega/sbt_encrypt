// Copyright (c) 2022, Very Good Ventures
// https://verygood.ventures
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.
import 'dart:convert';
import 'dart:typed_data';

import 'package:argon2/argon2.dart';
import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart';

/// Password derive
Future<List<int>> argon(String password, Uint8List salt) async {
  final parameters = Argon2Parameters(
    Argon2Parameters.ARGON2_d,
    salt,
    iterations: 2,
    memoryPowerOf2: 5,
  );
  final argon2 = Argon2BytesGenerator()..init(parameters);
  final passwordBytes = parameters.converter.convert(password);
  final result = Uint8List(32);
  argon2.generateBytes(passwordBytes, result, 0, result.length);
  return result;
}

/// encrypt data
Future<String> encrypt(String plainText, String password) async {
  // final iv = IV.fromSecureRandom(16);
  final salt = IV.fromSecureRandom(12).bytes;
  final key = await argon(password, salt);
  final algorithm = Chacha20(macAlgorithm: Hmac.sha256());
  final secretBox = await algorithm.encrypt(
    ascii.encode(plainText),
    secretKey: SecretKey(key.sublist(0, 32)),
    nonce: salt,
  );
  return base64.encode(secretBox.nonce + secretBox.cipherText);
}

/// decrypted data
Future<String> decrypt(String input, String password) async {
  final unpackaged = base64.decode(input);
  final salt = unpackaged.sublist(0, 12);
  final data = unpackaged.sublist(12);
  final secretBox = SecretBox(data, nonce: salt, mac: Mac([]));
  final key = await argon(password, salt);
  final algorithm = Chacha20(macAlgorithm: Hmac.sha256());
  final encrypted = await algorithm.decrypt(
    secretBox,
    secretKey: SecretKey(key.sublist(0, 32)),
  );
  return ascii.decode(encrypted);
}
