import 'package:ensemble/framework/error_handling.dart';
import 'package:ensemble/framework/storage_manager.dart';
import 'package:ensemble/framework/stub/auth_context_manager.dart';
import 'package:ensemble/util/utils.dart';
import 'package:ensemble_ts_interpreter/invokables/invokable.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/cupertino.dart';
import 'package:firebase_core/firebase_core.dart';

/// This abstract out different method of Sign In (local, custom, Firebase, Auth0, ...)
class AuthManager {
  static final AuthManager _instance = AuthManager._internal();

  AuthManager._internal();

  factory AuthManager() {
    return _instance;
  }

  Future<void> signInWithCredential(
      BuildContext context, SignInProvider signInProvider,
      {required AuthenticatedUser user,
      required String idToken,
      AuthToken? token}) async {
    if (signInProvider == SignInProvider.local) {
      return _signInLocally(context, user: user);
    } else if (signInProvider == SignInProvider.firebase) {}

    //FirebaseAuth.instance.signInWithCredential(AuthCredential(providerId: , signInMethod: signInMethod))
  }

  Future<void> _signInLocally(BuildContext context,
      {required AuthenticatedUser user, AuthToken? token}) async {
    // update the user information in storage
    await StorageManager().updateAuthenticatedUser(context, user: user);

    // TODO: think this through a bit
    // save the access token to storage. This will become
    // the bearer token to any API with serviceId = AuthProvider.id
    // if (token != null) {
    //   const FlutterSecureStorage().write(
    //       key: "${user.provider}_accessToken", value: token.token);
    // }
  }

  Future<void> _signInWithFirebase(BuildContext context,
      {required AuthenticatedUser user,
      required String idToken,
      AuthToken? token}) async {
    final credential = GoogleAuthProvider.credential(
        idToken: idToken, accessToken: token?.token);
    final UserCredential authResult =
        await FirebaseAuth.instanceFor(app: Firebase.app('customFirebase'))
            .signInWithCredential(credential);
    final User? user = authResult.user;
    if (user == null) {
      throw RuntimeError('Unable to Sign In');
    }
  }

  Future<void> signOut(BuildContext context) async {
    await StorageManager().clearAuthenticatedUser(context);
  }

  bool isSignedIn(BuildContext context) {
    return StorageManager().hasAuthenticatedUser();
  }
}

/// publicly exposed as Context
class AuthContextManagerImpl with Invokable implements AuthContextManager {

  @override
  Map<String, Function> getters() {
    return {
      'user': () => StorageManager().getAuthenticatedUser(),
    };
  }

  @override
  Map<String, Function> methods() {
    return {
      'isSignedIn': () => AuthManager().isSignedIn(Utils.globalAppKey.currentContext!),
      'signIn': _processSignIn,
      'signOut': () => AuthManager().signOut(Utils.globalAppKey.currentContext!),
    };
  }

  void _processSignIn(dynamic inputs) {
    Map? inputMap = Utils.getMap(inputs);
    if (inputMap != null) {
      // AuthManager().signIn(_buildContext, user: AuthenticatedUser(
      //     provider: AuthProvider.custom,
      //     id: Utils.optionalString(inputMap['id']),
      //     name: Utils.optionalString(inputMap['name']),
      //     email: Utils.optionalString(inputMap['email']),
      //     photo: Utils.optionalString(inputMap['photo'])),
      //   token: AuthToken(tokenType: TokenType.token, token: token)
      //
      // );
    }

    //AuthManager().signIn(_buildContext, user: user)
  }

  @override
  Map<String, Function> setters() {
    return {};
  }
}


class AuthToken {
  AuthToken({required this.tokenType, required this.token});

  TokenType tokenType;
  String token;
}

enum TokenType {
  token, // Authorization: <token>
  bearerToken // Authorization: Bearer <token>
}

enum SignInProvider {
  local, // store the login state locally on the client
  custom,
  firebase,
  auth0
}
