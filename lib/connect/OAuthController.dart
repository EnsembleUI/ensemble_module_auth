import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:developer' as developer;

import 'package:crypto/crypto.dart';
import 'package:ensemble/action/InvokeAPIController.dart';
import 'package:ensemble/ensemble.dart';
import 'package:ensemble/framework/action.dart';
import 'package:ensemble/framework/error_handling.dart';
import 'package:ensemble/framework/scope.dart';
import 'package:ensemble/framework/stub/oauth_controller.dart';
import 'package:ensemble/framework/stub/token_manager.dart';
import 'package:ensemble/screen_controller.dart';
import 'package:ensemble/util/http_utils.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

class OAuthControllerImpl implements OAuthController {
  static const accessTokenKey = '_accessToken';
  static const refreshTokenKey = '_refreshToken';

  @override
  Future<OAuthServiceToken?> authorize(BuildContext context, OAuthService service,
      {required String scope, bool forceNewTokens = false,
      InvokeAPIAction? tokenExchangeAPI}) async {
    // see if the tokens already exists
    const storage = FlutterSecureStorage();
    if (!forceNewTokens) {
      String? accessToken = await storage.read(key: service.name + accessTokenKey);
      String? refreshToken =
          await storage.read(key: service.name + refreshTokenKey);
      if (accessToken != null) {
        return OAuthServiceToken(
            accessToken: accessToken, refreshToken: refreshToken);
      }
    }

    OAuthServicePayload? servicePayload = await getServicePayload(service);
    if (servicePayload != null) {
      String codeVerifier = _generateCodeVerifier();
      String codeChallenge = _generateCodeChallenge(codeVerifier);
      String state = generateState();
      Uri uri = Uri.parse(servicePayload.authorizationURL);
      uri = uri.replace(queryParameters: {
        ...uri.queryParameters,
        ...{
          'response_type': 'code',
          'client_id': servicePayload.clientId,
          'redirect_uri': servicePayload.redirectUri,
          'scope': scope,
          'state': state,
          'code_challenge': codeChallenge,
          'code_challenge_method': 'S256'
        }
      });

      // authorize with the service
      final result = await FlutterWebAuth2.authenticate(
          url: uri.toString(),
          callbackUrlScheme: servicePayload.redirectScheme);
      final resultUri = Uri.parse(result);
      String? code = resultUri.queryParameters['code'];
      if (code != null && state == resultUri.queryParameters['state']) {

        // code exchange can be on the client or server
        OAuthServiceToken? token;
        if (tokenExchangeAPI == null) {
          token = await _getTokenFromClient(code: code,
              codeVerifier: codeVerifier, servicePayload: servicePayload);
        } else {
          token = await _getTokenFromServer(
              context,
              code: code,
              codeVerifier: codeVerifier,
              tokenExchangeAPI: tokenExchangeAPI,
              service: service,
              servicePayload: servicePayload);
        }
        if (token != null) {
          await storage.write(
              key: service.name + accessTokenKey, value: token.accessToken);
          if (token.refreshToken != null) {
            await storage.write(
                key: service.name + refreshTokenKey, value: token.refreshToken);
          }
          return token;
        }
      }
    }
    return null;
  }

  String _generateCodeVerifier() {
    var random = Random.secure();
    var values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64UrlEncode(values);
  }

  String _generateCodeChallenge(String codeVerifier) {
    var bytes = utf8.encode(codeVerifier);
    var digest = sha256.convert(bytes);
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }

  /// exchange OAuth code for token on the server
  Future<OAuthServiceToken?> _getTokenFromServer(BuildContext context,
      {required String code, required String codeVerifier,
        required InvokeAPIAction tokenExchangeAPI,
        required OAuthService service, required OAuthServicePayload servicePayload}) async {

    try {
      Response response = await InvokeAPIController().executeWithContext(
          context, tokenExchangeAPI, additionalInputs: { 'code': code, 'codeVerifier': codeVerifier });
      if (response.body != null) {
        return OAuthServiceToken(
            accessToken: response.body['access_token'],
            refreshToken: response.body['refresh_token']);
      }
    } catch (error) {
      // should we give user access to error object?
      developer.log(error.toString());
    }
    return null;
  }




    // var data = json.encode({
    //   'code': code,
    //   'serviceId': service.name,
    //   'token': JWT({'redirectUri': servicePayload.redirectUri})
    //       .sign(SecretKey(dotenv.env['OAUTH_TOKEN']!))
    // });
    // var response = await http.post(Uri.parse(tokenExchangeServer),
    //     body: data, headers: {'Content-Type': 'application/json'});
    // if (response.statusCode == 200) {
    //   var jsonResponse = json.decode(response.body);
    //   if (jsonResponse != null) {
    //     return OAuthServiceToken(
    //         accessToken: jsonResponse['access_token'],
    //         refreshToken: jsonResponse['refresh_token']);
    //   }
    // }
    // return null;
  }

  /// exchange OAuth code for token locally
  Future<OAuthServiceToken?> _getTokenFromClient({
      required String code,
      required String codeVerifier,
      required OAuthServicePayload servicePayload}) async {
    final response = await http.post(Uri.parse(servicePayload.tokenURL), body: {
        'client_id': servicePayload.clientId,
        'redirect_uri': servicePayload.redirectUri,
        'grant_type': 'authorization_code',
        'code': code,
        'code_verifier': codeVerifier
      });
    var jsonResponse = json.decode(response.body);
    if (jsonResponse != null) {
      return OAuthServiceToken(
          accessToken: jsonResponse['access_token'],
          refreshToken: jsonResponse['refresh_token']);
    }
    return null;
  }

  /// generate a unique state
  String generateState() {
    var raw = List<int>.generate(32, (index) => Random.secure().nextInt(256));
    return base64Url.encode(raw);
  }

  Future<OAuthServicePayload?> getServicePayload(OAuthService service) {
    if (service == OAuthService.google) {
      return getGoogleServicePayload(offline: true);
    } else if (service == OAuthService.microsoft) {
      return getMicrosoftServicePayload(tenantId: 'f3a999e9-2d73-4a55-86fb-0f90c0294c5f');
    } else if (service == OAuthService.yahoo) {
      return getYahooServicePayload();
    }
    return Future.value(null);
  }

  /// These will come from our server
  Future<OAuthServicePayload?> getGoogleServicePayload({required bool offline}) async {
    APICredential? credential = _getAPICredential(ServiceName.google);
    if (credential != null) {
      return Future.value(OAuthServicePayload(
          authorizationURL:
              "https://accounts.google.com/o/oauth2/v2/auth${offline ? '?access_type=offline&prompt=consent' : ''}",
          tokenURL: "https://oauth2.googleapis.com/token",
          clientId: credential.clientId,
          redirectUri: credential.redirectUri,
          redirectScheme: credential.redirectScheme));
    }
    return null;
  }

  Future<OAuthServicePayload?> getMicrosoftServicePayload({required String tenantId}) async {
    APICredential? credential = _getAPICredential(ServiceName.microsoft);
    if (credential != null) {
      return Future.value(OAuthServicePayload(
          authorizationURL: 'https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize',
          tokenURL: 'https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token',
          clientId: credential.clientId,
          redirectUri: credential.redirectUri,
          redirectScheme: credential.redirectScheme));
    }
    return null;
  }

  Future<OAuthServicePayload?> getYahooServicePayload() async {
    APICredential? credential = _getAPICredential(ServiceName.yahoo);
    if (credential != null) {
      return Future.value(OAuthServicePayload(
          authorizationURL: 'https://api.login.yahoo.com/oauth2/request_auth',
          tokenURL: '// to be added',
          clientId: credential.clientId,
          redirectUri: credential.redirectUri,
          redirectScheme: credential.redirectScheme));
    }
    return null;
  }

  APICredential? _getAPICredential(ServiceName serviceName) =>
      Ensemble().getServices()?.apiCredentials?[serviceName];

class OAuthServicePayload {
  OAuthServicePayload(
      {required this.authorizationURL,
        required this.tokenURL,
      required this.clientId,
      String? redirectUri,
      String? redirectScheme}) {
    if (redirectUri == null) {
      throw ConfigError(
          "API's redirectUri not found. Please double check your config.");
    }
    this.redirectUri = redirectUri;

    if (redirectUri.startsWith('https')) {
      this.redirectScheme = 'https';
    } else {
      // redirect scheme is required for custom scheme
      if (redirectScheme == null) {
        throw ConfigError(
            "API's redirectScheme is required for non-https scheme.");
      }
      this.redirectScheme = redirectScheme;
    }
  }

  String authorizationURL;
  String tokenURL;
  String clientId;

  // redirect can be https or a custom scheme e.g. myApp://
  // if redirectURL is a https URL, its scheme must be 'https'
  // if redirectURL is a custom scheme e.g. 'myApp://auth', its scheme should be e.g. 'myApp'
  late String redirectUri;
  late String redirectScheme;
}