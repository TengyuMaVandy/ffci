from django.conf.urls import url

from . import views

urlpatterns = [
    # ex: /hello/
    url(r'^$', views.index, name='index'),
]
