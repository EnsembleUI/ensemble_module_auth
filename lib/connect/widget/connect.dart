

import 'package:ensemble/framework/action.dart';
import 'package:ensemble/util/utils.dart';
import 'package:ensemble/widget/helpers/controllers.dart';
import 'package:ensemble_auth/signin/widget/sign_in_button.dart';

class ConnectController extends SignInButtonController {
  List<String>? initialScopes;

  // these are initialized in the widget (as they need initiator)
  InvokeAPIAction? tokenExchangeAPI;
  EnsembleAction? onAuthorized;
  EnsembleAction? onError;

  @override
  Map<String, Function> getBaseSetters() {
    Map<String, Function> setters = super.getBaseSetters();
    setters.addAll({
      'initialScopes': (scopes) => initialScopes = Utils.getListOfStrings(scopes),
    });
    return setters;
  }
}

class ConnectUtils {
  static String getScopesAsString(List<String>? scopes) {
    if (scopes != null) {
      return scopes.join(' ').trim();
    }
    return '';
  }
}