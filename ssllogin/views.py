# -*- coding: utf-8 -*-
from django.conf import settings
from django.core.urlresolvers import reverse 
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import views as auth_views
from django.http import HttpResponseRedirect, QueryDict

SESSION_KEY_PARAM = "sessionkey"
PICK_SESSION_URL_PARAM = "abs_ps"

def secure_login(request):
    """
    A replacement for Django's default login view that sends the user to an ssl url on
    a different domain ("settings.SSL_DOMAIN"). This is needed to work around GAEs limitation
    with ssl only working on ".appspot.com" domains.
    """
    if request.is_secure():
        login_response = auth_views.login(request)
        # Django's login view has a "light security check" that won't allow redirecting 
        # to absolute urls, so we have to do it manually (potentially spoiling the security)
        picks_url = request.GET.get(PICK_SESSION_URL_PARAM, None)
        if isinstance(login_response, HttpResponseRedirect) and picks_url:
            get = request.GET.copy()
            del get[PICK_SESSION_URL_PARAM]
            get[SESSION_KEY_PARAM] = request.session.session_key
            return HttpResponseRedirect("%s?%s" % (picks_url, get.urlencode()))
        else:
            return login_response
    elif not settings.DEBUG:
        get = request.GET.copy()
        get[PICK_SESSION_URL_PARAM] = request.build_absolute_uri(reverse(pick_session))
        next = "%s?%s" %(reverse(secure_login), get.urlencode())
        qd = QueryDict('').copy()
        qd[REDIRECT_FIELD_NAME] =  next
        qd[SESSION_KEY_PARAM] = request.session.session_key
        return HttpResponseRedirect("https://%s%s?%s" % (settings.SSL_DOMAIN, reverse(pick_session), qd.urlencode()))
    # No SSL on dev server, so just invoke the regular login view
    return auth_views.login(request)


def pick_session(request):
    """
    Take session from request "sessionkey" parameter and make it the current session
    Session key is cycled so that even if it leaks through the url it won't be usable.
    """
    session_key = request.GET[SESSION_KEY_PARAM]
    engine = __import__(settings.SESSION_ENGINE, {}, {}, [''])
    session = engine.SessionStore(session_key)
    session._session #touch 
    session.cycle_key()
    request.session = session
    return HttpResponseRedirect(request.GET[REDIRECT_FIELD_NAME])
