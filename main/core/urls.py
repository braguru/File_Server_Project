from django.urls import path
from . import views
from .views import Home

urlpatterns = [
    path('', views.login_user, name="login"),
    path('signup/', views.SignUp_user, name="signup"),
    path('admin_page/', views.login_user, name='admin_page'),
    path("logout/", views.logout_user, name="logout"),
    path('home/', Home.as_view(), name='home'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('change_password/', views.change_password, name='change_password'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
]