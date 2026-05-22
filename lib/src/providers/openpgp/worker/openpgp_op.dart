import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

import 'package:flutter/services.dart';
import 'package:openpgp/openpgp.dart';

const _binaryEnvelopePrefix = '__SECM_B64__:';

/// Operations the OpenPGP worker isolate can perform.
enum OpenPgpOp {
  decrypt,
  encrypt,
  encryptString,
  sign,
  verify,
  getPublicKeyMetadata,
  getPrivateKeyMetadata,
}

/// Long-lived worker-isolate entrypoint for OpenPGP operations.
///
/// One isolate = one resident OpenPGP FFI / platform-channel binding. By
/// reusing the same isolate across calls we avoid the ~40–80 ms per-request
/// cost that `compute()` pays to spawn a fresh VM and reinitialise the native
/// side.
///
/// The entrypoint is annotated with `@pragma('vm:entry-point')` so that the
/// tree-shaker never removes it in release builds.
@pragma('vm:entry-point')
void openPgpWorkerMain(SendPort mainSendPort) {
  final commandPort = ReceivePort();
  mainSendPort.send(commandPort.sendPort);

  bool bindingReady = false;

  commandPort.listen((dynamic message) async {
    final map = Map<dynamic, dynamic>.from(message as Map);
    final SendPort replyPort = map['replyPort'] as SendPort;
    final jobId = map['jobId'] as String;
    final op = OpenPgpOp.values.firstWhere((e) => e.name == map['op']);
    final payload = Map<String, Object?>.from(map['payload'] as Map);

    // Initialise the binary messenger the first time we receive a job so that
    // platform channels work inside this background isolate.
    if (!bindingReady) {
      final token = payload['_rootIsolateToken'];
      if (token is RootIsolateToken) {
        BackgroundIsolateBinaryMessenger.ensureInitialized(token);
      }
      bindingReady = true;
    }

    try {
      Object? result;
      switch (op) {
        case OpenPgpOp.decrypt:
          result = await _decrypt(payload);
        case OpenPgpOp.encrypt:
          result = await _encrypt(payload);
        case OpenPgpOp.encryptString:
          result = await _encryptString(payload);
        case OpenPgpOp.sign:
          result = await _sign(payload);
        case OpenPgpOp.verify:
          result = await _verify(payload);
        case OpenPgpOp.getPublicKeyMetadata:
          result = await _getPublicKeyMetadata(payload);
        case OpenPgpOp.getPrivateKeyMetadata:
          result = await _getPrivateKeyMetadata(payload);
      }
      replyPort.send({'jobId': jobId, 'success': true, 'result': result});
    } catch (e, st) {
      replyPort.send({
        'jobId': jobId,
        'success': false,
        'error': '$e',
        'stackTrace': '$st',
      });
    }
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────

Uint8List _bytes(Object? o) {
  if (o is TransferableTypedData) return o.materialize().asUint8List();
  if (o is Uint8List) return o;
  if (o is List<int>) return Uint8List.fromList(o);
  throw ArgumentError('Expected byte payload, got $o');
}

// ── Operation implementations ──────────────────────────────────────────────

Future<TransferableTypedData> _decrypt(Map<String, Object?> p) async {
  final decrypted = await OpenPGP.decrypt(
    utf8.decode(_bytes(p['encryptedData'])),
    utf8.decode(_bytes(p['privateKey'])),
    p['passphrase'] as String,
  );

  if (decrypted.startsWith(_binaryEnvelopePrefix)) {
    final b64 = decrypted.substring(_binaryEnvelopePrefix.length);
    return TransferableTypedData.fromList([base64Decode(b64)]);
  }

  // Backward compatibility for ciphertext generated before binary envelope.
  return TransferableTypedData.fromList([utf8.encode(decrypted)]);
}

Future<TransferableTypedData> _encrypt(Map<String, Object?> p) async {
  final payload = _bytes(p['data']);
  final textPayload = '$_binaryEnvelopePrefix${base64Encode(payload)}';

  final encrypted = await OpenPGP.encrypt(
    textPayload,
    utf8.decode(_bytes(p['recipientKey'])),
  );
  return TransferableTypedData.fromList([utf8.encode(encrypted)]);
}

Future<String> _encryptString(Map<String, Object?> p) async {
  return OpenPGP.encrypt(
    p['data'] as String,
    utf8.decode(_bytes(p['recipientKey']), allowMalformed: true),
  );
}

Future<TransferableTypedData> _sign(Map<String, Object?> p) async {
  final signature = await OpenPGP.signBytes(
    _bytes(p['data']),
    utf8.decode(_bytes(p['signingKey'])),
    p['passphrase'] as String,
  );
  return TransferableTypedData.fromList([signature]);
}

Future<bool> _verify(Map<String, Object?> p) async {
  return OpenPGP.verifyBytes(
    utf8.decode(_bytes(p['signature'])),
    _bytes(p['data']),
    utf8.decode(_bytes(p['publicKey'])),
  );
}

/// Returns a plain [Map] (sendable across isolate boundary) containing the
/// fields of the `openpgp` package's native [PublicKeyMetadata].
Future<Map<String, dynamic>> _getPublicKeyMetadata(
  Map<String, Object?> p,
) async {
  final meta = await OpenPGP.getPublicKeyMetadata(
    utf8.decode(_bytes(p['publicKey'])),
  );
  return {
    'algorithm': meta.algorithm,
    'keyId': meta.keyId,
    'keyIdShort': meta.keyIdShort,
    'creationTime': meta.creationTime,
    'fingerprint': meta.fingerprint,
    'keyIdNumeric': meta.keyIdNumeric,
    'isSubKey': meta.isSubKey,
    'canSign': meta.canSign,
    'canEncrypt': meta.canEncrypt,
    'identities': meta.identities
        .map(
          (id) => {
            'id': id.id,
            'name': id.name,
            'email': id.email,
            'comment': id.comment,
          },
        )
        .toList(),
  };
}

/// Returns a plain [Map] (sendable across isolate boundary) containing the
/// fields of the `openpgp` package's native [PrivateKeyMetadata].
Future<Map<String, dynamic>> _getPrivateKeyMetadata(
  Map<String, Object?> p,
) async {
  final meta = await OpenPGP.getPrivateKeyMetadata(
    utf8.decode(_bytes(p['privateKey'])),
  );
  return {
    'keyId': meta.keyId,
    'keyIdShort': meta.keyIdShort,
    'creationTime': meta.creationTime,
    'fingerprint': meta.fingerprint,
    'keyIdNumeric': meta.keyIdNumeric,
    'isSubKey': meta.isSubKey,
    'encrypted': meta.encrypted,
    'canSign': meta.canSign,
    'identities': meta.identities
        .map(
          (id) => {
            'id': id.id,
            'name': id.name,
            'email': id.email,
            'comment': id.comment,
          },
        )
        .toList(),
  };
}
