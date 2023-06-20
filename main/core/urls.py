from django.urls import path
from . import views
from .views import Home, Feed_Detail, send_file_page
from main.urls import admin

urlpatterns = [
    path('', views.login_user, name="login"),
    path('signup/', views.SignUp_user, name="signup"),
    # path('admin_page/', views.admin_page, name='admin_page'),
    path('admin/', admin.site.urls),
    path("logout/", views.logout_user, name="logout"),
    path('home/', Home.as_view(), name='home'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    # path('change_password/', views.change_password, name='change_password'),
    path('reset_password/<uidb64>/<token>', views.reset_password, name='reset_password'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('feed_page_detail/<slug:pk>/', Feed_Detail.as_view(), name="feed_detail" ),
    # path('send_file_page/<slug:pk>/', send_file_page.as_view(), name='send_page'),
    path('send_file_page/<int:id>/', views.send_file_page, name='send_page'),
]