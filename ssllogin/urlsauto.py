from django.conf.urls.defaults import *

rootpatterns = patterns('ssllogin.views',
    (r'^securelogin/$', 'secure_login'),
    (r'^securelogin/pick_session/$', 'pick_session'),

)
