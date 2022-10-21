// Copyright (c) 2022, Very Good Ventures
// https://verygood.ventures
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

import 'dart:convert';
import 'dart:typed_data';

import 'package:sbt_encrypt/src/sbt_encrypt.dart';
// ignore_for_file: prefer_const_constructors
import 'package:test/test.dart';

void main() {
  group('sbt encrypt test', () {
    test('argon2 derive', () async {
      const password = '121212';
      const salt = [158, 82, 111, 126, 245, 222, 179, 76, 133, 117, 16, 149];
      final result = await argon(password, Uint8List.fromList(salt));
      expect(
        base64.encode(result),
        'F30DpIwR02Iz7/A+61quxaPTQnqNvcNbFlSs83wZfT4=',
      );
    });
    test('can encode', () async {
      final encrypted = await encrypt('test', '121212');
      final decrypted = await decrypt(encrypted, '121212');
      expect('test', decrypted);
    });

    test('decypt data', () async {
      const data = 'z7E6AV2FtDqvHB5Ral9OIQ==';
      final decrypted = await decrypt(data, '121212');
      expect('test', decrypted);
    });
  });
}
