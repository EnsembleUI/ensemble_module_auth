import 'dart:io';

import 'package:ensemble/ensemble.dart';
import 'package:ensemble/framework/action.dart';
import 'package:ensemble/framework/error_handling.dart';
import 'package:ensemble/framework/event.dart';
import 'package:ensemble/framework/extensions.dart';
import 'package:ensemble/framework/view/page.dart';
import 'package:ensemble/framework/widget/widget.dart';
import 'package:ensemble/screen_controller.dart';
import 'package:ensemble/util/utils.dart';
import 'package:ensemble/widget/stub_widgets.dart';
import 'package:ensemble_auth/signin/auth_manager.dart';
import 'package:ensemble_auth/signin/widget/sign_in_button.dart';
import 'package:ensemble_ts_interpreter/invokables/invokable.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart';
import 'package:auth0_flutter/auth0_flutter.dart';


class SignInWithAuth0Impl extends StatefulWidget
    with
        Invokable
    implements SignInWithAuth0, HasController<SignInWithAuth0ImplController, SignInWithAuth0ImplState> {
  static const defaultLabel = 'Sign In';
  SignInWithAuth0Impl({super.key});

  final SignInWithAuth0ImplController _controller = SignInWithAuth0ImplController();

  @override
  get controller => _controller;

  @override
  State<StatefulWidget> createState() => SignInWithAuth0ImplState();

  @override
  Map<String, Function> getters() => {};

  @override
  Map<String, Function> methods() => {};

  @override
  Map<String, Function> setters() => {
    'widget': (widgetDef) => _controller.widgetDef = widgetDef,
    'scheme': (scheme) => _controller.scheme = scheme,
    'provider': (value) => _controller.provider =
        SignInProvider.values.from(value),
    'onAuthenticated': (action) => _controller.onAuthenticated =
        EnsembleAction.fromYaml(action, initiator: this),
    'onSignedIn': (action) => _controller.onSignedIn =
        EnsembleAction.fromYaml(action, initiator: this),
    'onError': (action) => _controller.onError =
        EnsembleAction.fromYaml(action, initiator: this),
    'scopes': (value) => _controller.scopes =
        Utils.getListOfStrings(value) ?? _controller.scopes,
  };

  @override
  List<String> passthroughSetters() {
    // TODO: implement passthroughSetters
    throw UnimplementedError();
  }
}

class SignInWithAuth0ImplController extends SignInButtonController {
  dynamic widgetDef;
  String scheme = 'https';
  List<String> scopes = [];

  SignInProvider? provider;
  EnsembleAction? onAuthenticated;
  EnsembleAction? onSignedIn;
  EnsembleAction? onError;
}

class SignInWithAuth0ImplState extends WidgetState<SignInWithAuth0Impl> {
  late Credentials? _credentials;
  late Auth0 _auth0;
  Widget? displayWidget;

  @override
  void initState() {
    super.initState();

    _auth0 = Auth0(getAuthDomain(), getClientId());
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // build the display widget
    if (widget._controller.widgetDef != null) {
      displayWidget = DataScopeWidget.getScope(context)
          ?.buildWidgetFromDefinition(widget._controller.widgetDef);
    }
  }

  @override
  Widget buildWidget(BuildContext context) {
    return SignInButton(
        defaultLabel: SignInWithAuth0Impl.defaultLabel,
        buttonController: widget._controller,
        onTap: _handleSignIn
    );
  }

  Future<void> _handleSignIn() async {
    try {
      _credentials = await _auth0.webAuthentication(scheme: widget._controller.scheme).login();

      if (_credentials != null) {
        _onAuthenticated(_credentials!);
      }
    } on Exception catch (e, s) {
      debugPrint('login error: $e - stack: $s');
    }
  }

  // TODO: handle signout
  Future<void> _handleSignOut() async {
    await _auth0.webAuthentication(scheme: widget._controller.scheme).logout();

    _credentials = null;
  }

  Future<void> _onAuthenticated(Credentials credentials) async {
    UserProfile userProfile = credentials.user;
    AuthenticatedUser user = AuthenticatedUser(
        client: SignInClient.auth0,
        provider: widget._controller.provider,
        id: userProfile.email,
        name: userProfile.name,
        email: userProfile.email,
        photo: userProfile.pictureUrl?.toString());

    // trigger the callback. This can be used to sign in on the server
    if (widget._controller.onAuthenticated != null) {
      ScreenController()
          .executeAction(context, widget._controller.onAuthenticated!,
          event: EnsembleEvent(widget, data: {
            'user': user,
            'idToken': credentials.idToken,
            'refreshToken': credentials.refreshToken,
            'accessToken': credentials.accessToken
          }));
    }

    if (widget._controller.provider != SignInProvider.server) {
      AuthToken token = AuthToken(
            tokenType: TokenType.bearerToken,
            token: credentials.accessToken);
      await AuthManager().signInWithCredential(
          context,
          user: user,
          idToken: credentials.idToken,
          token: token);

      // trigger onSignIn callback
      if (widget._controller.onSignedIn != null) {
        ScreenController()
            .executeAction(context, widget._controller.onSignedIn!,
            event: EnsembleEvent(widget, data: {
              'user': user
            }));
      }
    }
  }

  String getAuthDomain() {
    final authDomain = Ensemble().getSignInServices()?.serverUri;
    if (authDomain == null) {
      throw LanguageError("Auth0 SignIn provider domain is required.",
          recovery: "Please check your configuration.");
    }
    return authDomain;
  }
  String getClientId() {
    SignInCredential? credential =
    Ensemble().getSignInServices()?.signInCredentials?[ServiceName.auth0];
    String? clientId;
    // Auth0 seems to use the same clientId for all three clients, but leaving for flexibility
    if (kIsWeb) {
      clientId = credential?.webClientId;
    } else if (Platform.isAndroid) {
      clientId = credential?.androidClientId;
    } else if (Platform.isIOS) {
      clientId = credential?.iOSClientId;
    }
    if (clientId != null) {
      return clientId;
    }
    throw LanguageError("Auth0 SignIn provider client ID is required.",
        recovery: "Please check your configuration.");
  }
}
