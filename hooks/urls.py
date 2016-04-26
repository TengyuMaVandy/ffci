from django.conf.urls import url

from hooks.views import IndexView, StatusTagView
from . import views

urlpatterns = [
    # ex: /hooks/
    url(r'^$', IndexView.as_view(), name='index'),
    url(r"^status_tag.svg/$", StatusTagView.as_view(), name="status_tag")
]
