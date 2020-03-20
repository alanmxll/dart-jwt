import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

String secret = 'sangatiberga';

void main() async {
  var server = await HttpServer.bind(InternetAddress.loopbackIPv4, 4000);
  server.listen((request) async {
    if (request.uri.path == '/login') {
      request.response.write(_generateToken());
    } else if (request.uri.path == '/test') {
      if (_testToken(request)) {
        request.response.write('Seja bem vindo!');
      } else {
        request.response.write('Acesso NEGADO!');
      }
    } else {
      request.response.statusCode = 404;
      request.response.write('Página não encontrada.');
    }

    await request.response.close();
  });
}

bool _testToken(HttpRequest request) {
  var token = request.headers['Authorization'][0].split(' ')[1];
  var tokens = token.split('.');

  String header64 = tokens[0];
  String payload64 = tokens[1];
  Map payload = jsonDecode(utf8.decode(base64Decode(payload64)));
  String sign64 = tokens[2];

  var hmac = Hmac(sha256, secret.codeUnits);
  var digest = hmac.convert("$header64.$payload64".codeUnits);
  String signGlobal = base64Encode(digest.bytes);

  return sign64 == signGlobal &&
      DateTime.now().millisecondsSinceEpoch < payload['exp'];
}

String _generateToken() {
  var header = {"alg": "HS256", "typ": "JWT"};

  String header64 = base64Encode(jsonEncode(header).codeUnits);

  var payload = {
    "sub": 1,
    "name": "Alan Maxwell",
    "exp": DateTime.now().millisecondsSinceEpoch + 60000
  };

  String payload64 = base64Encode(jsonEncode(payload).codeUnits);

  var hmac = Hmac(sha256, secret.codeUnits);
  var digest = hmac.convert("$header64.$payload64".codeUnits);
  String sign = base64Encode(digest.bytes);

  return "$header64.$payload64.$sign";
}
