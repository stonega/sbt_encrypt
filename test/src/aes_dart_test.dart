// Copyright (c) 2022, Very Good Ventures
// https://verygood.ventures
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

import 'package:aes_dart/aes_dart.dart';
// ignore_for_file: prefer_const_constructors
import 'package:test/test.dart';

void main() {
  group('AesDart', () {
    test('can encode', () async {
      final encrypted = await aesEncrypt('test', '121212');
      final decrypted = await aesDecrypt(encrypted, '121212');
      expect('test', decrypted);
    });

    test('decypt data', () async {
      const data =
          '1Gyw5Al31seI7s/V7Ma5gQ3K4/lxmuqpr4OHG0FPAfxPRkraylz8I7HvA1/h5E4g';
      final decrypted = await aesDecrypt(data, '121212');
      expect('test', decrypted);
    });
  });
}
