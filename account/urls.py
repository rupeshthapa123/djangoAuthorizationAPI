from django.urls import path
from account.views import UserRegistrationView, UserLoginView
from account.views import UserProfileView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name="profile")
]
